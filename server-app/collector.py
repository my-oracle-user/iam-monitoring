import json
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlparse


DEFAULT_SERVER_HEALTH_THRESHOLDS = {
    "load1": {
        "warning": {"ge": 8},
        "critical": {"ge": 16},
    },
    "memoryUsedPercent": {
        "warning": {"ge": 85},
        "critical": {"ge": 92},
    },
    "rootDiskUsedPercent": {
        "warning": {"ge": 70},
        "critical": {"ge": 80},
    },
    "refreshDiskUsedPercent": {
        "warning": {"ge": 70},
        "critical": {"ge": 80},
    },
    "cpuIoWaitPercent": {
        "warning": {"ge": 15},
        "critical": {"ge": 30},
    },
    "cpuIdlePercent": {
        "warning": {"le": 15},
        "critical": {"le": 5},
    },
}


def lines(text):
    if not text:
        return []
    return [line.strip() for line in str(text).splitlines() if line.strip()]


def percent(part, whole):
    if not whole:
        return 0
    return round((float(part) / float(whole)) * 100, 1)


def safe_float(value):
    if value in (None, "", "-"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def threshold_value(value):
    if value in (None, "", "-"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def threshold_matches(value, rule):
    if not isinstance(rule, dict) or not rule:
        return False
    numeric_value = threshold_value(value)
    matched = False
    for operator, threshold in rule.items():
        operator = str(operator).strip().lower()
        numeric_threshold = threshold_value(threshold)
        if operator in ("gt", "ge", "lt", "le"):
            if numeric_value is None or numeric_threshold is None:
                return False
            matched = True
            if operator == "gt" and not (numeric_value > numeric_threshold):
                return False
            if operator == "ge" and not (numeric_value >= numeric_threshold):
                return False
            if operator == "lt" and not (numeric_value < numeric_threshold):
                return False
            if operator == "le" and not (numeric_value <= numeric_threshold):
                return False
            continue
        left = str(value).strip().lower()
        right = str(threshold).strip().lower()
        matched = True
        if operator == "eq" and left != right:
            return False
        if operator == "ne" and left == right:
            return False
    return matched


def threshold_severity(value, rules):
    rules = rules or {}
    if threshold_matches(value, rules.get("critical")):
        return "critical"
    if threshold_matches(value, rules.get("warning")):
        return "warning"
    return "healthy"


def build_server_health(server_snapshot):
    server_snapshot = server_snapshot or {}
    if not server_snapshot.get("reachable"):
        return {
            "status": "down",
            "checks": {},
            "thresholds": DEFAULT_SERVER_HEALTH_THRESHOLDS,
        }

    uptime = server_snapshot.get("uptime") or {}
    memory = server_snapshot.get("memory") or {}
    root_disk = server_snapshot.get("rootDisk") or {}
    refresh_disk = server_snapshot.get("refreshDisk") or {}
    cpu_breakdown = uptime.get("cpuBreakdown") or {}

    checks = {
        "load1": {
            "label": "Load Average (1m)",
            "value": uptime.get("load1"),
            "severity": threshold_severity(uptime.get("load1"), DEFAULT_SERVER_HEALTH_THRESHOLDS["load1"]),
        },
        "memoryUsedPercent": {
            "label": "Memory Used",
            "value": memory.get("usedPercent"),
            "severity": threshold_severity(
                memory.get("usedPercent"),
                DEFAULT_SERVER_HEALTH_THRESHOLDS["memoryUsedPercent"],
            ),
        },
        "rootDiskUsedPercent": {
            "label": "Root Disk Used",
            "value": root_disk.get("usedPercent"),
            "severity": threshold_severity(
                root_disk.get("usedPercent"),
                DEFAULT_SERVER_HEALTH_THRESHOLDS["rootDiskUsedPercent"],
            ),
        },
        "refreshDiskUsedPercent": {
            "label": "Refresh Disk Used",
            "value": refresh_disk.get("usedPercent"),
            "severity": threshold_severity(
                refresh_disk.get("usedPercent"),
                DEFAULT_SERVER_HEALTH_THRESHOLDS["refreshDiskUsedPercent"],
            ) if refresh_disk.get("size") else "healthy",
        },
        "cpuIoWaitPercent": {
            "label": "CPU IO Wait",
            "value": cpu_breakdown.get("ioWaitPercent"),
            "severity": threshold_severity(
                cpu_breakdown.get("ioWaitPercent"),
                DEFAULT_SERVER_HEALTH_THRESHOLDS["cpuIoWaitPercent"],
            ),
        },
        "cpuIdlePercent": {
            "label": "CPU Idle",
            "value": cpu_breakdown.get("idlePercent"),
            "severity": threshold_severity(
                cpu_breakdown.get("idlePercent"),
                DEFAULT_SERVER_HEALTH_THRESHOLDS["cpuIdlePercent"],
            ),
        },
    }

    overall = "healthy"
    for item in checks.values():
        severity = item.get("severity")
        if severity == "critical":
            overall = "critical"
            break
        if severity == "warning" and overall == "healthy":
            overall = "warning"

    return {
        "status": overall,
        "checks": checks,
        "thresholds": DEFAULT_SERVER_HEALTH_THRESHOLDS,
    }


def run_local(command, timeout=25):
    try:
        process = subprocess.Popen(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        output, _ = process.communicate(timeout=timeout)
        return {"exit_code": process.returncode, "output": (output or "").strip()}
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        return {"exit_code": 1, "output": ((output or "").strip() or "Local command timed out.")}


def run_ssh(target, command, timeout=25):
    auth_type = str(target.get("authType") or "password").lower()
    remote_command = "bash -lc {0}".format(shlex.quote(command))
    if target.get("sudoRequired"):
        if auth_type == "password" and target.get("password"):
            remote_command = (
                "if [ \"$(id -u)\" -eq 0 ]; then "
                "bash -lc {cmd}; "
                "else "
                "printf '%s\\n' {password} | sudo -S -p '' bash -lc {cmd}; "
                "fi"
            ).format(
                cmd=shlex.quote(command),
                password=shlex.quote(str(target.get("password") or "")),
            )
        else:
            remote_command = (
                "if [ \"$(id -u)\" -eq 0 ]; then "
                "bash -lc {cmd}; "
                "else "
                "sudo -n bash -lc {cmd}; "
                "fi"
            ).format(cmd=shlex.quote(command))
    ssh_args = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "LogLevel=ERROR",
        "-p",
        str(target.get("port") or 22),
    ]

    private_key_path = target.get("privateKeyPath")
    if auth_type == "private_key" and private_key_path:
        ssh_args.extend(["-i", private_key_path])

    ssh_args.append("{0}@{1}".format(target.get("username"), target.get("host")))
    ssh_args.append(remote_command)

    command_args = list(ssh_args)
    if auth_type == "password":
        command_args = ["sshpass", "-p", str(target.get("password") or "")] + ssh_args
    elif auth_type == "private_key" and target.get("passphrase"):
        command_args = [
            "sshpass",
            "-P",
            "Enter passphrase for key",
            "-p",
            str(target.get("passphrase") or ""),
        ] + ssh_args

    try:
        process = subprocess.run(
            command_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=timeout,
            check=False,
        )
        return {
            "exit_code": process.returncode,
            "output": (process.stdout or "").strip(),
        }
    except FileNotFoundError as exc:
        return {"exit_code": 1, "output": "{0} not found on the monitoring host.".format(exc.filename)}
    except subprocess.TimeoutExpired as exc:
        return {"exit_code": 1, "output": ((exc.stdout or "").strip() or "SSH command timed out.")}


def run_target(target, command, timeout=25):
    if target.get("mode") == "local":
        return run_local(command, timeout=timeout)
    return run_ssh(target, command, timeout=timeout)


def _matching_ssh_profiles(primary, secondary):
    primary = primary or {}
    secondary = secondary or {}
    return (
        str(primary.get("host") or "").strip() == str(secondary.get("host") or "").strip()
        and str(primary.get("port") or 22).strip() == str(secondary.get("port") or 22).strip()
        and str(primary.get("username") or "").strip() == str(secondary.get("username") or "").strip()
        and str(primary.get("sshMode") or "").strip() == str(secondary.get("sshMode") or "").strip()
        and str(primary.get("authType") or "").strip() == str(secondary.get("authType") or "").strip()
    )


def _effective_environment_server(environment):
    server = dict(environment.get("server") or {})
    weblogic = environment.get("weblogic") or {}
    admin_host = weblogic.get("adminHost") or {}
    if _matching_ssh_profiles(server, admin_host):
        if not str(server.get("password") or "").strip() and str(admin_host.get("password") or "").strip():
            server["password"] = admin_host.get("password") or ""
        if not str(server.get("privateKeyPath") or "").strip() and str(admin_host.get("privateKeyPath") or "").strip():
            server["privateKeyPath"] = admin_host.get("privateKeyPath") or ""
        if not str(server.get("passphrase") or "").strip() and str(admin_host.get("passphrase") or "").strip():
            server["passphrase"] = admin_host.get("passphrase") or ""
    return server


def parse_memory(text):
    for line in lines(text):
        if line.startswith("Mem:"):
            parts = re.split(r"\s+", line)
            if len(parts) >= 7:
                total_mb = int(parts[1])
                used_mb = int(parts[2])
                free_mb = int(parts[3])
                available_mb = int(parts[6])
                return {
                    "totalMb": total_mb,
                    "usedMb": used_mb,
                    "freeMb": free_mb,
                    "availableMb": available_mb,
                    "usedPercent": percent(used_mb, total_mb),
                }
    return None


def parse_disk(text):
    output_lines = lines(text)
    if len(output_lines) < 2:
        return None
    parts = re.split(r"\s+", output_lines[-1])
    if len(parts) < 6:
        return None
    return {
        "filesystem": parts[0],
        "size": parts[1],
        "used": parts[2],
        "available": parts[3],
        "usedPercent": float(parts[4].replace("%", "")),
        "mount": parts[5],
    }


def humanize_bytes(value):
    if value in (None, ""):
        return None
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    amount = float(value)
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024.0
        index += 1
    if index == 0:
        return "{0:.0f} {1}".format(amount, units[index])
    return "{0:.1f} {1}".format(amount, units[index])


def resolve_existing_directory(target, candidates):
    paths = [str(item or "").strip() for item in (candidates or []) if str(item or "").strip()]
    if not paths:
        return ""
    command = "for path in {0}; do if [ -d \"$path\" ]; then printf '%s' \"$path\"; break; fi; done".format(
        " ".join(shlex.quote(path) for path in paths)
    )
    result = run_target(target, command)
    if result.get("exit_code") != 0:
        return ""
    return str(result.get("output") or "").strip()


def directory_size_label(target, directory_path):
    path = str(directory_path or "").strip()
    if not path:
        return None
    result = run_target(
        target,
        "if [ -d {0} ]; then du -sk {0} 2>/dev/null | awk '{{print $1}}'; fi".format(shlex.quote(path)),
    )
    if result.get("exit_code") != 0:
        return None
    output = str(result.get("output") or "").strip()
    if output.isdigit():
        return humanize_bytes(int(output) * 1024)
    return output or None


def schema_match_files(target, schema_directory):
    path = str(schema_directory or "").strip()
    if not path:
        return []
    result = run_target(
        target,
        "if [ -d {0} ]; then cd {0} && grep -RilE 'attribute|objectClasses' . 2>/dev/null | sed 's#^\\./##'; fi".format(
            shlex.quote(path)
        ),
    )
    if result.get("exit_code") != 0:
        return []
    return [line for line in lines(result.get("output")) if line]


def parse_meminfo_proc(text):
    values = {}
    for raw_line in lines(text):
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        parts = value.strip().split()
        if not parts:
            continue
        try:
            values[key.strip()] = int(parts[0]) * 1024
        except (TypeError, ValueError):
            continue

    total_bytes = values.get("MemTotal")
    available_bytes = values.get("MemAvailable")
    if total_bytes is None:
        return None
    if available_bytes is None:
        available_bytes = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    used_bytes = max(total_bytes - available_bytes, 0)
    return {
        "totalBytes": total_bytes,
        "usedBytes": used_bytes,
        "availableBytes": available_bytes,
        "totalMb": int(round(total_bytes / (1024.0 * 1024.0))),
        "usedMb": int(round(used_bytes / (1024.0 * 1024.0))),
        "availableMb": int(round(available_bytes / (1024.0 * 1024.0))),
        "usedPercent": percent(used_bytes, total_bytes),
    }


def parse_disk_bytes(text):
    output_lines = lines(text)
    if len(output_lines) < 2:
        return None
    parts = re.split(r"\s+", output_lines[-1])
    if len(parts) < 6:
        return None
    try:
        size_bytes = int(parts[1])
        used_bytes = int(parts[2])
        available_bytes = int(parts[3])
    except (TypeError, ValueError):
        return None
    return {
        "filesystem": parts[0],
        "totalBytes": size_bytes,
        "usedBytes": used_bytes,
        "availableBytes": available_bytes,
        "size": humanize_bytes(size_bytes),
        "used": humanize_bytes(used_bytes),
        "available": humanize_bytes(available_bytes),
        "usedPercent": float(parts[4].replace("%", "")),
        "mount": parts[5],
    }


def read_cpu_stat_snapshot(text):
    for raw_line in lines(text):
        if not raw_line.startswith("cpu "):
            continue
        parts = raw_line.split()
        values = []
        for item in parts[1:11]:
            try:
                values.append(int(item))
            except (TypeError, ValueError):
                values.append(0)
        keys = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"]
        return dict(zip(keys, values))
    return None


def cpu_breakdown(first, second):
    if not first or not second:
        return {
            "userPercent": None,
            "systemPercent": None,
            "ioWaitPercent": None,
            "idlePercent": None,
        }

    def total(values):
        return sum(values.get(key, 0) for key in ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"))

    idle_first = first.get("idle", 0) + first.get("iowait", 0)
    idle_second = second.get("idle", 0) + second.get("iowait", 0)
    non_idle_first = total(first) - idle_first
    non_idle_second = total(second) - idle_second
    total_delta = max((idle_second + non_idle_second) - (idle_first + non_idle_first), 1)
    user_delta = max((second.get("user", 0) + second.get("nice", 0)) - (first.get("user", 0) + first.get("nice", 0)), 0)
    system_delta = max(
        (second.get("system", 0) + second.get("irq", 0) + second.get("softirq", 0))
        - (first.get("system", 0) + first.get("irq", 0) + first.get("softirq", 0)),
        0,
    )
    io_wait_delta = max(second.get("iowait", 0) - first.get("iowait", 0), 0)
    idle_delta = max(idle_second - idle_first, 0)
    return {
        "userPercent": round((user_delta * 100.0) / total_delta, 2),
        "systemPercent": round((system_delta * 100.0) / total_delta, 2),
        "ioWaitPercent": round((io_wait_delta * 100.0) / total_delta, 2),
        "idlePercent": round((idle_delta * 100.0) / total_delta, 2),
    }


def parse_uptime(text, cpu_count):
    load1 = 0.0
    load5 = 0.0
    load15 = 0.0
    match = re.search(r"load average:\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)", text or "")
    if match:
        load1 = float(match.group(1))
        load5 = float(match.group(2))
        load15 = float(match.group(3))
    return {
        "raw": text or "",
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "cpuCount": cpu_count,
        "cpuPressure": percent(load1, cpu_count) if cpu_count else 0,
    }


def extract_xmx_mb(arguments):
    match = re.search(r"-Xmx(\d+)([mMgG])", arguments or "")
    if not match:
        return None

    amount = int(match.group(1))
    if match.group(2).lower() == "g":
        return amount * 1024
    return amount


def parse_jstat(text):
    output_lines = lines(text)
    if len(output_lines) < 2:
        return None

    headers = re.split(r"\s+", output_lines[0])
    values = re.split(r"\s+", output_lines[1])
    if len(values) < len(headers):
        return None

    raw = {}
    for index, header in enumerate(headers):
        raw[header] = values[index] if index < len(values) else None

    def value_as_int(key):
        value = safe_float(raw.get(key))
        return int(value) if value is not None else None

    return {
        "survivor0Percent": safe_float(raw.get("S0")),
        "survivor1Percent": safe_float(raw.get("S1")),
        "edenPercent": safe_float(raw.get("E")),
        "oldGenPercent": safe_float(raw.get("O")),
        "metaspacePercent": safe_float(raw.get("M")),
        "classSpacePercent": safe_float(raw.get("CCS")),
        "youngGcCount": value_as_int("YGC"),
        "youngGcTimeSeconds": safe_float(raw.get("YGCT")),
        "fullGcCount": value_as_int("FGC"),
        "fullGcTimeSeconds": safe_float(raw.get("FGCT")),
        "concurrentGcCount": value_as_int("CGC"),
        "concurrentGcTimeSeconds": safe_float(raw.get("CGCT")),
        "totalGcTimeSeconds": safe_float(raw.get("GCT")),
    }


def parse_sectioned_output(text):
    sections = {}
    current = None
    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        heading = re.match(r"^-{3}\s*(.*?)\s*-{3}$", stripped)
        if heading:
            current = heading.group(1).strip()
            sections[current] = []
            continue
        if current:
            sections.setdefault(current, []).append(raw_line.rstrip())
    return sections


def parse_key_value_banner_output(text):
    banner = ""
    values = {}
    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if not banner and ":" not in stripped:
            banner = stripped
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        values[key.strip()] = value.strip()
    return {
        "banner": banner,
        "values": values,
    }


def parse_oud_status(text):
    summary = {}
    listeners = []
    backends = []
    sections = parse_sectioned_output(text)

    for section_name in ("Server Status", "Server Details"):
        for raw_line in sections.get(section_name, []):
            stripped = raw_line.strip()
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            summary[key.strip()] = value.strip()

    for raw_line in sections.get("Connection Handlers", []):
        stripped = raw_line.strip()
        if (
            not stripped
            or stripped.startswith("Address:Port")
            or stripped.startswith("-------------")
        ):
            continue
        match = re.match(r"^(.*?)\s+:\s+(.*?)\s+:\s+(.*?)$", stripped)
        if not match:
            continue
        listeners.append({
            "addressPort": match.group(1).strip(),
            "protocol": match.group(2).strip(),
            "state": match.group(3).strip(),
        })

    block = {}

    def flush_backend():
        if not block:
            return
        entries_value = block.get("Entries")
        backends.append({
            "baseDn": block.get("Base DN"),
            "backendId": block.get("Backend ID"),
            "entries": int(entries_value) if entries_value and str(entries_value).isdigit() else entries_value,
            "replication": block.get("Replication"),
        })
        block.clear()

    for raw_line in sections.get("Data Sources", []):
        stripped = raw_line.strip()
        if not stripped:
            flush_backend()
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        block[key.strip()] = value.strip()
    flush_backend()

    return {
        "summary": summary,
        "listeners": listeners,
        "backends": backends,
    }


def parse_oud_replication(text):
    sections = []
    current = None
    lines_buffer = []

    def flush_section():
        nonlocal current, lines_buffer
        if current is None:
            return
        table_lines = []
        for raw_line in lines_buffer:
            stripped = raw_line.rstrip()
            if not stripped.strip():
                continue
            if stripped.strip().startswith("Server ") or re.fullmatch(r"[-=:\s]+", stripped.strip()):
                continue
            table_lines.append(stripped)

        parsed_rows = []
        pending_prefix = ""
        for raw_line in table_lines:
            stripped = raw_line.rstrip()
            delimiter_count = len(re.findall(r"\s+:\s+", stripped))
            if delimiter_count == 0:
                pending_prefix += stripped.strip()
                continue
            combined = "{0}{1}".format(pending_prefix, stripped.lstrip()) if pending_prefix else stripped
            pending_prefix = ""
            parts = [part.strip() for part in re.split(r"\s+:\s+", combined) if part is not None]
            server_value = str(parts[0]).strip() if parts else ""
            if not server_value or re.fullmatch(r"[-=:\s]+", server_value) or not re.search(r"[A-Za-z0-9]", server_value):
                continue
            if current.get("enabled"):
                if len(parts) >= 7:
                    parsed_rows.append({
                        "server": server_value,
                        "entries": parts[1],
                        "missingChanges": parts[2],
                        "ageOfOldestMissingChange": parts[3],
                        "port": parts[4],
                        "status": parts[5],
                        "conflicts": parts[6],
                    })
            else:
                if len(parts) >= 3:
                    parsed_rows.append({
                        "server": server_value,
                        "entries": parts[1],
                        "changeLog": parts[2],
                    })

        current["servers"] = parsed_rows
        sections.append(current)
        current = None
        lines_buffer = []

    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        heading_match = re.match(r"^(.*?)\s*-\s*Replication\s+(Enabled|Disabled)$", stripped)
        if heading_match:
            flush_section()
            current = {
                "baseDn": heading_match.group(1).strip(),
                "enabled": heading_match.group(2).strip().lower() == "enabled",
                "servers": [],
            }
            continue
        if current is not None:
            lines_buffer.append(raw_line)

    flush_section()
    return sections


def build_monitoring_target(monitoring_config):
    return {
        "mode": "local",
        "host": monitoring_config.get("host") or "localhost",
        "port": 22,
        "username": "",
        "authType": "password",
        "password": "",
        "privateKeyPath": "",
        "passphrase": "",
    }


def build_environment_target(environment):
    server = _effective_environment_server(environment)
    bootstrap = environment.get("bootstrap") or {}
    username = server.get("username") or "root"
    sudo_required = bool(server.get("sudoRequired"))
    runtime_key_path = str(bootstrap.get("runtimeKeyPath") or "").strip()
    bootstrap_ready = str(bootstrap.get("status") or "").strip().lower() == "ready"
    if bootstrap_ready and runtime_key_path:
        return {
            "mode": server.get("mode") or "ssh",
            "host": server.get("host") or "",
            "port": server.get("port") or 22,
            "username": username,
            "sshMode": "root_key" if username == "root" and not sudo_required else ("user_key_sudo" if sudo_required else "user_key"),
            "authType": "private_key",
            "sudoRequired": sudo_required,
            "password": "",
            "privateKeyPath": runtime_key_path,
            "passphrase": "",
        }
    return {
        "mode": server.get("mode") or "ssh",
        "host": server.get("host") or "",
        "port": server.get("port") or 22,
        "username": username,
        "sshMode": server.get("sshMode") or "root_password",
        "authType": server.get("authType") or "password",
        "sudoRequired": sudo_required,
        "password": server.get("password") or "",
        "privateKeyPath": server.get("privateKeyPath") or "",
        "passphrase": server.get("passphrase") or "",
    }


def build_weblogic_target(environment, fallback_target=None):
    weblogic = environment.get("weblogic") or {}
    admin_host = weblogic.get("adminHost") or {}
    if not str(admin_host.get("host") or "").strip():
        return fallback_target or build_environment_target(environment)
    return {
        "mode": admin_host.get("mode") or "ssh",
        "host": admin_host.get("host") or "",
        "port": admin_host.get("port") or 22,
        "username": admin_host.get("username") or "root",
        "sshMode": admin_host.get("sshMode") or "root_password",
        "authType": admin_host.get("authType") or "password",
        "sudoRequired": bool(admin_host.get("sudoRequired")),
        "password": admin_host.get("password") or "",
        "privateKeyPath": admin_host.get("privateKeyPath") or "",
        "passphrase": admin_host.get("passphrase") or "",
    }


def build_oaa_target(environment, fallback_target=None):
    oaa = environment.get("oaa") or {}
    kube_host = oaa.get("kubeHost") or {}
    if not str(kube_host.get("host") or "").strip():
        return fallback_target or build_environment_target(environment)
    return {
        "mode": kube_host.get("mode") or "ssh",
        "host": kube_host.get("host") or "",
        "port": kube_host.get("port") or 22,
        "username": kube_host.get("username") or "root",
        "sshMode": kube_host.get("sshMode") or "root_password",
        "authType": kube_host.get("authType") or "password",
        "sudoRequired": bool(kube_host.get("sudoRequired")),
        "password": kube_host.get("password") or "",
        "privateKeyPath": kube_host.get("privateKeyPath") or "",
        "passphrase": kube_host.get("passphrase") or "",
    }


def get_server_snapshot(target, script_directory=None, process_matchers=None):
    hostname = run_target(target, "hostname")
    if hostname["exit_code"] != 0:
        return {
            "reachable": False,
            "status": "down",
            "actualHostname": None,
            "error": hostname["output"] or "Connection failed.",
        }

    kernel = run_target(target, "uname -r")
    os_name = run_target(target, "grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"'")
    cpu = run_target(target, "nproc")
    uptime = run_target(target, "uptime")
    uptime_seconds = run_target(target, "cut -d' ' -f1 /proc/uptime 2>/dev/null || echo 0")
    load_average = run_target(target, "cat /proc/loadavg 2>/dev/null || echo ''")
    meminfo = run_target(target, "cat /proc/meminfo 2>/dev/null || echo ''")
    memory = run_target(target, "free -m")
    root_disk = run_target(target, "df -P -h /")
    root_disk_bytes = run_target(target, "df -P -B1 /")
    refresh_disk = run_target(target, "if [ -d /refresh ]; then df -P -h /refresh; fi")
    refresh_disk_bytes = run_target(target, "if [ -d /refresh ]; then df -P -B1 /refresh; fi")
    cpu_stat_first = run_target(target, "cat /proc/stat 2>/dev/null || echo ''")
    time.sleep(0.35)
    cpu_stat_second = run_target(target, "cat /proc/stat 2>/dev/null || echo ''")

    cpu_count = int(cpu["output"]) if re.match(r"^\d+$", cpu["output"] or "") else 0
    memory_payload = parse_meminfo_proc(meminfo.get("output")) or parse_memory(memory["output"])
    root_disk_payload = parse_disk_bytes(root_disk_bytes.get("output")) or parse_disk(root_disk["output"])
    refresh_disk_payload = parse_disk_bytes(refresh_disk_bytes.get("output")) or parse_disk(refresh_disk["output"])
    uptime_payload = parse_uptime((uptime["output"] or "").strip(), cpu_count)
    try:
        uptime_payload["uptimeSeconds"] = int(float((uptime_seconds.get("output") or "0").strip()))
    except (TypeError, ValueError):
        uptime_payload["uptimeSeconds"] = 0

    load_parts = re.split(r"\s+", (load_average.get("output") or "").strip())
    if len(load_parts) >= 3:
        try:
            uptime_payload["load1"] = round(float(load_parts[0]), 2)
            uptime_payload["load5"] = round(float(load_parts[1]), 2)
            uptime_payload["load15"] = round(float(load_parts[2]), 2)
            uptime_payload["cpuPressure"] = percent(uptime_payload["load1"], cpu_count) if cpu_count else 0
        except (TypeError, ValueError):
            pass
    uptime_payload["cpuBreakdown"] = cpu_breakdown(
        read_cpu_stat_snapshot(cpu_stat_first.get("output")),
        read_cpu_stat_snapshot(cpu_stat_second.get("output")),
    )

    scripts = []
    if script_directory:
        script_result = run_target(
            target,
            "if [ -d {0} ]; then ls {0} | head -n 12; fi".format(shlex.quote(script_directory)),
        )
        scripts = lines(script_result["output"])

    processes = []
    if process_matchers:
        pattern = "|".join([item for item in process_matchers if item])
        process_result = run_target(
            target,
            "ps -eo user=,pid=,comm=,args= --sort=user | egrep -i {0} | grep -v egrep | head -n 12".format(
                shlex.quote(pattern)
            ),
        )
        processes = lines(process_result["output"])

    return {
        "reachable": True,
        "status": "healthy",
        "actualHostname": (hostname["output"] or "").strip(),
        "kernel": (kernel["output"] or "").strip(),
        "os": (os_name["output"] or "").strip(),
        "uptime": uptime_payload,
        "memory": memory_payload,
        "rootDisk": root_disk_payload,
        "refreshDisk": refresh_disk_payload,
        "scriptDirectory": script_directory,
        "scripts": scripts,
        "processes": processes,
    }


def get_app_check(target, check):
    result = run_target(
        target,
        "if command -v curl >/dev/null 2>&1; then curl -k -L -s -o /dev/null -w '%{{http_code}} %{{time_total}}' {0}; else echo NO_CURL; fi".format(
            shlex.quote(check.get("url"))
        ),
    )

    output = (result.get("output") or "").strip()
    match = re.match(r"^(\d{3})\s+([0-9.]+)$", output)
    status = "down"
    status_text = "No response"
    http_code = None
    response_time_ms = None

    if match:
        http_code = int(match.group(1))
        response_time_ms = int(round(float(match.group(2)) * 1000))
        if 200 <= http_code < 400:
            status = "healthy"
            status_text = "Reachable"
        elif http_code in (401, 403):
            status = "warning"
            status_text = "Responding with authentication gate"
        elif http_code == 0:
            status_text = "Connection failed or service is not listening"
        else:
            status_text = "HTTP {0}".format(http_code)
    elif output == "NO_CURL":
        status_text = "curl not available on target"
    elif output:
        status_text = output

    return {
        "product": check.get("product") or "generic",
        "name": check.get("name"),
        "url": check.get("url"),
        "status": status,
        "statusText": status_text,
        "httpCode": http_code,
        "responseTimeMs": response_time_ms,
    }


def collect_app_checks(target, environment):
    checks = []
    if (environment.get("products") or {}).get("oam"):
        checks.extend((environment.get("oam") or {}).get("checks") or [])
    if (environment.get("products") or {}).get("oud"):
        checks.extend((environment.get("oud") or {}).get("checks") or [])
    if (environment.get("products") or {}).get("oig"):
        checks.extend((environment.get("oig") or {}).get("checks") or [])
    return [get_app_check(target, check) for check in checks]


def get_oud_root_dse(target, settings, fallback_password):
    ldap_url = settings.get("ldapUrl")
    bind_dn = settings.get("bindDn")
    bind_password = settings.get("bindPassword") or fallback_password
    if not ldap_url or not bind_dn or not bind_password:
        return {}

    command = (
        "ldapsearch -x -H {0} -D {1} -w {2} -b \"\" -s base "
        "\"(objectClass=*)\" namingContexts vendorName vendorVersion"
    ).format(
        shlex.quote(ldap_url),
        shlex.quote(bind_dn),
        shlex.quote(bind_password),
    )
    result = run_target(target, command)
    root = {
        "namingContexts": [],
        "vendorName": None,
        "vendorVersion": None,
    }

    for raw_line in lines(result.get("output")):
        if raw_line.startswith("namingContexts:"):
            root["namingContexts"].append(raw_line.split(":", 1)[1].strip())
        elif raw_line.startswith("vendorName:"):
            root["vendorName"] = raw_line.split(":", 1)[1].strip()
        elif raw_line.startswith("vendorVersion:"):
            root["vendorVersion"] = raw_line.split(":", 1)[1].strip()

    return root


def python_string_literal(value):
    return str(value or "").replace("\\", "\\\\").replace("'", "\\'")


def normalize_weblogic_connect_url(admin_url):
    text = str(admin_url or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else "t3://{0}".format(text))
    scheme = str(parsed.scheme or "t3").lower()
    host = parsed.hostname or parsed.path
    port = parsed.port
    if not host:
        return ""
    if scheme in ("http", "https"):
        scheme = "t3s" if scheme == "https" else "t3"
    elif scheme not in ("t3", "t3s"):
        scheme = "t3"
    return "{0}://{1}{2}".format(scheme, host, ":{0}".format(port) if port else "")


def parse_weblogic_deployments(text):
    deployments = []
    for raw_line in lines(text):
        match = re.match(r"^(.*?)\s*:\s*(STATE_[A-Z_]+)\s*$", raw_line)
        if not match:
            continue
        deployments.append({
            "name": match.group(1).strip(),
            "state": match.group(2).strip(),
        })
    return deployments


def parse_weblogic_server_inventory(text):
    rows = []
    header_seen = False
    for raw_line in lines(text):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("TYPE | SERVER | STATE | MACHINE | LISTEN_ADDRESS | IP | PORT | SSL_PORT | CLUSTER"):
            header_seen = True
            continue
        if not header_seen or "|" not in stripped:
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) < 9:
            continue
        rows.append({
            "type": parts[0],
            "name": parts[1],
            "state": parts[2],
            "machine": parts[3],
            "listenAddress": parts[4],
            "ip": parts[5],
            "port": parts[6],
            "sslPort": parts[7],
            "cluster": parts[8],
        })
    return rows


def parse_weblogic_stuck_threads(text):
    rows = []
    header_seen = False

    def maybe_int(value):
        text_value = str(value or "").strip()
        if re.fullmatch(r"-?\d+", text_value):
            return int(text_value)
        return None

    for raw_line in lines(text):
        stripped = raw_line.strip()
        if not stripped:
            continue
        arrow_match = re.match(
            r"^(?P<server>.+?)\s*->\s*StuckThreads:\s*(?P<stuck>[^|]+)\|\s*HoggingThreads:\s*(?P<hogging>.+?)$",
            stripped,
        )
        if arrow_match:
            stuck_threads = maybe_int(arrow_match.group("stuck"))
            hogging_threads = maybe_int(arrow_match.group("hogging"))
            rows.append({
                "server": arrow_match.group("server").strip(),
                "stuckThreads": stuck_threads,
                "hoggingThreads": hogging_threads,
                "error": "" if stuck_threads is not None and hogging_threads is not None else "Unable to fetch thread info",
            })
            continue
        if stripped.startswith("SERVER | STUCK_THREADS | HOGGING_THREADS"):
            header_seen = True
            continue
        if not header_seen or "|" not in stripped:
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) < 3:
            continue
        stuck_threads = maybe_int(parts[1])
        hogging_threads = maybe_int(parts[2])
        rows.append({
            "server": parts[0],
            "stuckThreads": stuck_threads,
            "hoggingThreads": hogging_threads,
            "error": "" if stuck_threads is not None and hogging_threads is not None else "Unable to fetch thread info",
        })
    return rows


def parse_weblogic_jdbc_pools(text):
    rows = []
    header_seen = False

    def maybe_int(value):
        text_value = str(value or "").strip()
        if re.fullmatch(r"-?\d+", text_value):
            return int(text_value)
        return None

    for raw_line in lines(text):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("SERVER | DATASOURCE | ACTIVE | WAITING"):
            header_seen = True
            continue
        if not header_seen or "|" not in stripped:
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) < 4:
            continue
        active_connections = maybe_int(parts[2])
        waiting_connections = maybe_int(parts[3])
        if active_connections is None or waiting_connections is None:
            continue
        rows.append({
            "server": parts[0],
            "dataSource": parts[1],
            "activeConnections": active_connections,
            "waitingConnections": waiting_connections,
        })
    return rows


def parse_weblogic_runtime_value(value):
    text_value = str(value or "").strip()
    if re.fullmatch(r"-?\d+", text_value):
        return int(text_value)
    if re.fullmatch(r"-?\d+\.\d+", text_value):
        return float(text_value)
    return text_value


def parse_weblogic_runtime_groups(text):
    section_map = {
        "jta": "jtaTransactions",
        "jms": "jmsDestinations",
        "jvm": "jvmRuntime",
        "threadPool": "threadPoolRuntime",
        "jdbcHealth": "jdbcHealth",
        "socket": "socketRuntime",
        "workManager": "workManagers",
    }
    grouped = {value: {} for value in section_map.values()}
    header_seen = False
    for raw_line in lines(text):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("SECTION | SERVER | NAME | METRIC | VALUE"):
            header_seen = True
            continue
        if not header_seen or "|" not in stripped:
            continue
        parts = [part.strip() for part in stripped.split("|", 4)]
        if len(parts) < 5:
            continue
        section, server, name, metric, value = parts
        target_key = section_map.get(section)
        if not target_key or not metric:
            continue
        row_key = "{0}\n{1}".format(server, name)
        row = grouped[target_key].setdefault(row_key, {"server": server, "name": name})
        row[metric] = parse_weblogic_runtime_value(value)

    result = {}
    for key, rows in grouped.items():
        result[key] = list(rows.values())
    for row in result.get("jmsDestinations", []):
        row["destination"] = row.pop("name", "")
    for row in result.get("jdbcHealth", []):
        row["dataSource"] = row.pop("name", "")
    for row in result.get("workManagers", []):
        row["workManager"] = row.pop("name", "")
    return result


def run_wlst_script(target, wlst_path, script_body, timeout=180):
    command = (
        "scriptfile=$(mktemp /tmp/iam-monitoring-wlst.XXXXXX.py) && "
        "trap 'rm -f \"$scriptfile\"' EXIT && "
        "cat > \"$scriptfile\" <<'PY'\n"
        "{0}\n"
        "PY\n"
        "{1} \"$scriptfile\""
    ).format(
        script_body.rstrip(),
        shlex.quote(wlst_path),
    )
    return command, run_target(target, command, timeout=timeout)


def weblogic_profile_configured(environment):
    weblogic = environment.get("weblogic") or {}
    admin_host = weblogic.get("adminHost") or {}
    products = environment.get("products") or {}
    return bool(
        products.get("weblogic")
        or products.get("oam")
        or products.get("oig")
        or products.get("soa")
        or weblogic.get("enabled")
        or str(weblogic.get("adminUrl") or "").strip()
        or str(weblogic.get("oracleHome") or "").strip()
        or str(admin_host.get("host") or "").strip()
    )


def get_weblogic_metrics(target, environment, progress=None):
    if not weblogic_profile_configured(environment):
        return None

    products = environment.get("products") or {}
    target = build_weblogic_target(environment, target)
    settings = environment.get("weblogic") or {}
    jstat_path = settings.get("jstatPath")
    admin_url = str(settings.get("adminUrl") or "").strip()
    admin_username = str(settings.get("adminUsername") or "").strip()
    admin_password = str(settings.get("adminPassword") or "").strip()
    oracle_home = str(settings.get("oracleHome") or "").strip()
    server_inventory = []
    server_inventory_error = None
    server_inventory_command = ""
    deployment_connect_url = normalize_weblogic_connect_url(admin_url)
    deployment_command = ""
    deployment_error = None
    deployments = []
    stuck_thread_command = ""
    stuck_thread_error = None
    stuck_threads = []
    jdbc_pool_command = ""
    jdbc_pool_error = None
    jdbc_pools = []
    runtime_metrics_command = ""
    runtime_metrics_error = None
    runtime_groups = {
        "jtaTransactions": [],
        "jmsDestinations": [],
        "jvmRuntime": [],
        "threadPoolRuntime": [],
        "jdbcHealth": [],
        "socketRuntime": [],
        "workManagers": [],
    }
    configuration_error = None
    weblogic_ready = bool(oracle_home and admin_username and admin_password and deployment_connect_url)

    if weblogic_ready:
        wlst_path = "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/"))
        if callable(progress):
            progress("Starting WLST server inventory collection from ORACLE_HOME/oracle_common/common/bin/wlst.sh.")
        inventory_script = (
            "from java.net import InetAddress\n"
            "connect('{0}','{1}','{2}')\n"
            "print('TYPE | SERVER | STATE | MACHINE | LISTEN_ADDRESS | IP | PORT | SSL_PORT | CLUSTER')\n"
            "domainRuntime()\n"
            "runtime_map = {{}}\n"
            "for r in domainRuntimeService.getServerRuntimes():\n"
            "    runtime_map[r.getName()] = r.getState()\n"
            "domainConfig()\n"
            "for server in cmo.getServers():\n"
            "    name = server.getName()\n"
            "    machine = server.getMachine().getName() if server.getMachine() else 'None'\n"
            "    listen_address = server.getListenAddress() or '0.0.0.0'\n"
            "    port = str(server.getListenPort())\n"
            "    ssl_port = 'None'\n"
            "    ssl = server.getSSL()\n"
            "    if ssl:\n"
            "        ssl_port = str(ssl.getListenPort())\n"
            "    cluster = server.getCluster().getName() if server.getCluster() else 'None'\n"
            "    state = runtime_map.get(name, 'UNKNOWN')\n"
            "    server_type = 'ADMIN' if name == 'AdminServer' else 'MANAGED'\n"
            "    ip_value = 'None'\n"
            "    try:\n"
            "        resolver = listen_address\n"
            "        if resolver in ('', '0.0.0.0', '::') and server.getMachine() and server.getMachine().getNodeManager():\n"
            "            resolver = server.getMachine().getNodeManager().getListenAddress() or resolver\n"
            "        if resolver and resolver not in ('0.0.0.0', '::'):\n"
            "            ip_value = InetAddress.getByName(resolver).getHostAddress()\n"
            "    except:\n"
            "        pass\n"
            "    print(server_type + ' | ' + name + ' | ' + state + ' | ' + machine + ' | ' + listen_address + ' | ' + ip_value + ' | ' + port + ' | ' + ssl_port + ' | ' + cluster)\n"
            "exit()\n"
        ).format(
            python_string_literal(admin_username),
            python_string_literal(admin_password),
            python_string_literal(deployment_connect_url),
        )
        server_inventory_command, inventory_result = run_wlst_script(target, wlst_path, inventory_script)
        server_inventory = parse_weblogic_server_inventory(inventory_result.get("output"))
        inventory_output = str(inventory_result.get("output") or "").strip()
        if server_inventory:
            if callable(progress):
                progress("WLST server inventory returned {0} server row(s).".format(len(server_inventory)))
        else:
            server_inventory_error = inventory_output or "WLST server inventory command failed."
            if callable(progress):
                progress("WLST server inventory returned no parsed rows.")

        if callable(progress):
            progress("Starting WLST deployment-state collection from ORACLE_HOME/oracle_common/common/bin/wlst.sh.")
        deployment_script = (
            "connect('{0}','{1}','{2}')\n"
            "domainRuntime()\n"
            "cd('/AppRuntimeStateRuntime/AppRuntimeStateRuntime')\n"
            "apps = cmo.getApplicationIds()\n"
            "print('\\n===== Application Deployment Status =====\\n')\n"
            "for app in apps:\n"
            "    print(app + ' : ' + cmo.getCurrentState(app, 'AdminServer'))\n"
            "print('\\n=========================================\\n')\n"
            "exit()\n"
        ).format(
            python_string_literal(admin_username),
            python_string_literal(admin_password),
            python_string_literal(deployment_connect_url),
        )
        deployment_command, deployment_result = run_wlst_script(target, wlst_path, deployment_script)
        deployments = parse_weblogic_deployments(deployment_result.get("output"))
        deployment_output = str(deployment_result.get("output") or "").strip()
        if deployments:
            if callable(progress):
                progress("WLST deployment-state returned {0} deployment row(s).".format(len(deployments)))
        else:
            deployment_error = deployment_output or "WLST deployment status command failed."
            if callable(progress):
                progress("WLST deployment-state returned no parsed rows.")

        if callable(progress):
            progress("Starting WLST stuck-thread collection from ORACLE_HOME/oracle_common/common/bin/wlst.sh.")
        stuck_thread_script = (
            "connect('{0}','{1}','{2}')\n"
            "domainRuntime()\n"
            "print('SERVER | STUCK_THREADS | HOGGING_THREADS')\n"
            "cd('/ServerRuntimes')\n"
            "for name in ls(returnMap='true'):\n"
            "    try:\n"
            "        cd('/ServerRuntimes/' + name + '/ThreadPoolRuntime/ThreadPoolRuntime')\n"
            "        stuck = cmo.getStuckThreadCount()\n"
            "        hogging = cmo.getHoggingThreadCount()\n"
            "        print(name + ' | ' + str(stuck) + ' | ' + str(hogging))\n"
            "    except:\n"
            "        print(name + ' | ERROR | ERROR')\n"
            "    cd('/ServerRuntimes')\n"
            "exit()\n"
        ).format(
            python_string_literal(admin_username),
            python_string_literal(admin_password),
            python_string_literal(deployment_connect_url),
        )
        stuck_thread_command, stuck_thread_result = run_wlst_script(target, wlst_path, stuck_thread_script)
        stuck_threads = parse_weblogic_stuck_threads(stuck_thread_result.get("output"))
        stuck_thread_output = str(stuck_thread_result.get("output") or "").strip()
        if stuck_threads:
            if callable(progress):
                progress("WLST stuck-thread collection returned {0} server row(s).".format(len(stuck_threads)))
        else:
            stuck_thread_error = stuck_thread_output or "WLST stuck-thread command failed."
            if callable(progress):
                progress("WLST stuck-thread collection returned no parsed rows.")

        if callable(progress):
            progress("Starting WLST JDBC connection pool collection from ORACLE_HOME/oracle_common/common/bin/wlst.sh.")
        jdbc_pool_script = (
            "connect('{0}','{1}','{2}')\n"
            "domainRuntime()\n"
            "print('SERVER | DATASOURCE | ACTIVE | WAITING')\n"
            "for runtime in domainRuntimeService.getServerRuntimes():\n"
            "    server_name = runtime.getName()\n"
            "    try:\n"
            "        jdbc_service = runtime.getJDBCServiceRuntime()\n"
            "        data_sources = jdbc_service.getJDBCDataSourceRuntimeMBeans() if jdbc_service else []\n"
            "        for data_source in data_sources:\n"
            "            print(server_name + ' | ' + data_source.getName() + ' | ' + str(data_source.getActiveConnectionsCurrentCount()) + ' | ' + str(data_source.getWaitingForConnectionCurrentCount()))\n"
            "    except:\n"
            "        pass\n"
            "exit()\n"
        ).format(
            python_string_literal(admin_username),
            python_string_literal(admin_password),
            python_string_literal(deployment_connect_url),
        )
        jdbc_pool_command, jdbc_pool_result = run_wlst_script(target, wlst_path, jdbc_pool_script)
        jdbc_pools = parse_weblogic_jdbc_pools(jdbc_pool_result.get("output"))
        jdbc_pool_output = str(jdbc_pool_result.get("output") or "").strip()
        if jdbc_pools:
            if callable(progress):
                progress("WLST JDBC connection pool collection returned {0} data source row(s).".format(len(jdbc_pools)))
        else:
            jdbc_pool_error = jdbc_pool_output or "WLST JDBC connection pool command failed."
            if callable(progress):
                progress("WLST JDBC connection pool collection returned no parsed rows.")

        if callable(progress):
            progress("Starting WLST extended runtime collection for JTA, JMS, JVM, thread pool, JDBC health, sockets, and WorkManagers.")
        runtime_metrics_script = (
            "connect('{0}','{1}','{2}')\n"
            "domainRuntime()\n"
            "print('SECTION | SERVER | NAME | METRIC | VALUE')\n"
            "def clean(value):\n"
            "    if value is None:\n"
            "        return ''\n"
            "    return str(value).replace('|', '/').replace('\\n', ' ').replace('\\r', ' ')\n"
            "def emit(section, server, name, metric, value):\n"
            "    print(section + ' | ' + clean(server) + ' | ' + clean(name) + ' | ' + clean(metric) + ' | ' + clean(value))\n"
            "def emit_attr(section, server, name, metric, bean, method_name):\n"
            "    try:\n"
            "        method = getattr(bean, method_name)\n"
            "        emit(section, server, name, metric, method())\n"
            "    except:\n"
            "        emit(section, server, name, metric, 'ERROR')\n"
            "for runtime in domainRuntimeService.getServerRuntimes():\n"
            "    server = runtime.getName()\n"
            "    try:\n"
            "        jta = runtime.getJTARuntime()\n"
            "        for metric, method_name in [('activeTransactionsTotalCount','getActiveTransactionsTotalCount'),('transactionTotalCount','getTransactionTotalCount'),('committedTotalCount','getCommittedTotalCount'),('rolledBackTotalCount','getRolledBackTotalCount'),('heuristicsTotalCount','getHeuristicsTotalCount'),('secondsActiveTotalCount','getSecondsActiveTotalCount')]:\n"
            "            emit_attr('jta', server, server, metric, jta, method_name)\n"
            "    except:\n"
            "        emit('jta', server, server, 'error', 'JTARuntime unavailable')\n"
            "    try:\n"
            "        jvm = runtime.getJVMRuntime()\n"
            "        for metric, method_name in [('heapFreeCurrent','getHeapFreeCurrent'),('heapSizeCurrent','getHeapSizeCurrent'),('heapFreePercent','getHeapFreePercent'),('javaVersion','getJavaVersion'),('uptime','getUptime')]:\n"
            "            emit_attr('jvm', server, server, metric, jvm, method_name)\n"
            "    except:\n"
            "        emit('jvm', server, server, 'error', 'JVMRuntime unavailable')\n"
            "    try:\n"
            "        thread_pool = runtime.getThreadPoolRuntime()\n"
            "        for metric, method_name in [('executeThreadTotalCount','getExecuteThreadTotalCount'),('executeThreadIdleCount','getExecuteThreadIdleCount'),('pendingUserRequestCount','getPendingUserRequestCount'),('queueLength','getQueueLength'),('hoggingThreadCount','getHoggingThreadCount'),('stuckThreadCount','getStuckThreadCount'),('throughput','getThroughput')]:\n"
            "            emit_attr('threadPool', server, server, metric, thread_pool, method_name)\n"
            "    except:\n"
            "        emit('threadPool', server, server, 'error', 'ThreadPoolRuntime unavailable')\n"
            "    try:\n"
            "        socket_runtime = runtime.getSocketRuntime()\n"
            "        for metric, method_name in [('socketsOpenedTotalCount','getSocketsOpenedTotalCount'),('socketsClosedTotalCount','getSocketsClosedTotalCount'),('currentOpenSocketCount','getCurrentOpenSocketCount')]:\n"
            "            emit_attr('socket', server, server, metric, socket_runtime, method_name)\n"
            "    except:\n"
            "        emit('socket', server, server, 'error', 'SocketRuntime unavailable')\n"
            "    try:\n"
            "        jdbc_service = runtime.getJDBCServiceRuntime()\n"
            "        data_sources = jdbc_service.getJDBCDataSourceRuntimeMBeans() if jdbc_service else []\n"
            "        for data_source in data_sources:\n"
            "            name = data_source.getName()\n"
            "            for metric, method_name in [('failuresToReconnectCount','getFailuresToReconnectCount'),('leakedConnectionCount','getLeakedConnectionCount'),('currCapacity','getCurrCapacity'),('state','getState'),('activeConnectionsCurrentCount','getActiveConnectionsCurrentCount'),('waitingForConnectionCurrentCount','getWaitingForConnectionCurrentCount')]:\n"
            "                emit_attr('jdbcHealth', server, name, metric, data_source, method_name)\n"
            "    except:\n"
            "        emit('jdbcHealth', server, server, 'error', 'JDBCServiceRuntime unavailable')\n"
            "    try:\n"
            "        jms_runtime = runtime.getJMSRuntime()\n"
            "        jms_servers = jms_runtime.getJMSServers() if jms_runtime else []\n"
            "        for jms_server in jms_servers:\n"
            "            destinations = jms_server.getDestinations() if jms_server else []\n"
            "            for destination in destinations:\n"
            "                name = jms_server.getName() + '/' + destination.getName()\n"
            "                for metric, method_name in [('messagesCurrentCount','getMessagesCurrentCount'),('messagesPendingCount','getMessagesPendingCount'),('messagesReceivedCount','getMessagesReceivedCount'),('consumersCurrentCount','getConsumersCurrentCount'),('bytesCurrentCount','getBytesCurrentCount')]:\n"
            "                    emit_attr('jms', server, name, metric, destination, method_name)\n"
            "    except:\n"
            "        emit('jms', server, server, 'error', 'JMSRuntime unavailable')\n"
            "    try:\n"
            "        work_managers = runtime.getWorkManagerRuntimes()\n"
            "        for work_manager in work_managers:\n"
            "            name = work_manager.getName()\n"
            "            for metric, method_name in [('pendingRequests','getPendingRequests'),('completedRequests','getCompletedRequests'),('stuckThreadCount','getStuckThreadCount')]:\n"
            "                emit_attr('workManager', server, name, metric, work_manager, method_name)\n"
            "    except:\n"
            "        emit('workManager', server, server, 'error', 'WorkManagerRuntimes unavailable')\n"
            "exit()\n"
        ).format(
            python_string_literal(admin_username),
            python_string_literal(admin_password),
            python_string_literal(deployment_connect_url),
        )
        runtime_metrics_command, runtime_metrics_result = run_wlst_script(target, wlst_path, runtime_metrics_script, timeout=240)
        runtime_groups = parse_weblogic_runtime_groups(runtime_metrics_result.get("output"))
        runtime_metrics_output = str(runtime_metrics_result.get("output") or "").strip()
        runtime_row_count = sum(len(value) for value in runtime_groups.values())
        if runtime_row_count:
            if callable(progress):
                progress("WLST extended runtime collection returned {0} metric row group(s).".format(runtime_row_count))
        else:
            runtime_metrics_error = runtime_metrics_output or "WLST extended runtime collection failed."
            if callable(progress):
                progress("WLST extended runtime collection returned no parsed rows.")
    else:
        missing = []
        if not oracle_home:
            missing.append("ORACLE_HOME")
        if not admin_url:
            missing.append("WebLogic Admin URL")
        if not admin_username:
            missing.append("WebLogic Admin Username")
        if not admin_password:
            missing.append("WebLogic Admin Password")
        if missing:
            missing_text = "Missing WebLogic deployment settings: {0}.".format(", ".join(missing))
            server_inventory_error = missing_text
            deployment_error = missing_text
            stuck_thread_error = missing_text
            jdbc_pool_error = missing_text
            runtime_metrics_error = missing_text
            configuration_error = missing_text

    server_names = [item.get("name") for item in server_inventory if item.get("name")]
    process_patterns = ["Dweblogic.Name={0}".format(name) for name in server_names] if server_names else []

    servers = []
    if process_patterns:
        process_result = run_target(
            target,
            "ps -eo pid=,nlwp=,rss=,args= | egrep {0} | grep -v grep".format(shlex.quote("|".join(process_patterns))),
        )

        for process_line in lines(process_result.get("output")):
            match = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", process_line)
            if not match:
                continue

            pid = int(match.group(1))
            threads = int(match.group(2))
            rss_kb = int(match.group(3))
            arguments = match.group(4)
            name_match = re.search(r"-Dweblogic.Name=([^\s]+)", arguments)
            server_name = name_match.group(1) if name_match else "Unknown"

            heap = None
            if jstat_path:
                jstat_result = run_target(target, "{0} -gcutil {1} 2>/dev/null".format(shlex.quote(jstat_path), pid))
                if jstat_result.get("exit_code") == 0:
                    heap = parse_jstat(jstat_result.get("output"))

            servers.append({
                "name": server_name,
                "pid": pid,
                "threads": threads,
                "rssMb": round(rss_kb / 1024.0, 1),
                "xmxMb": extract_xmx_mb(arguments),
                "heap": heap,
                "status": "running",
            })

    order_map = dict((name, index) for index, name in enumerate(server_names))
    servers.sort(key=lambda item: order_map.get(item.get("name"), 999))

    found_names = [item.get("name") for item in servers]
    missing_servers = [name for name in server_names if name not in found_names]
    active_deployments = [item for item in deployments if item.get("state") == "STATE_ACTIVE"]
    inactive_deployments = [item for item in deployments if item.get("state") != "STATE_ACTIVE"]
    total_stuck_threads = sum(item.get("stuckThreads") or 0 for item in stuck_threads)
    total_hogging_threads = sum(item.get("hoggingThreads") or 0 for item in stuck_threads)
    servers_with_stuck_threads = [item.get("server") for item in stuck_threads if (item.get("stuckThreads") or 0) > 0]
    servers_with_hogging_threads = [item.get("server") for item in stuck_threads if (item.get("hoggingThreads") or 0) > 0]
    total_active_connections = sum(item.get("activeConnections") or 0 for item in jdbc_pools)
    total_waiting_connections = sum(item.get("waitingConnections") or 0 for item in jdbc_pools)

    def metric_number(row, key):
        value = (row or {}).get(key)
        if isinstance(value, (int, float)):
            return value
        text_value = str(value or "").strip()
        if re.fullmatch(r"-?\d+", text_value):
            return int(text_value)
        if re.fullmatch(r"-?\d+\.\d+", text_value):
            return float(text_value)
        return 0

    jta_transactions = runtime_groups.get("jtaTransactions") or []
    jms_destinations = runtime_groups.get("jmsDestinations") or []
    jvm_runtime = runtime_groups.get("jvmRuntime") or []
    thread_pool_runtime = runtime_groups.get("threadPoolRuntime") or []
    jdbc_health = runtime_groups.get("jdbcHealth") or []
    socket_runtime = runtime_groups.get("socketRuntime") or []
    work_managers = runtime_groups.get("workManagers") or []
    heap_used_percent_values = [
        max(0, 100 - metric_number(item, "heapFreePercent"))
        for item in jvm_runtime
        if "heapFreePercent" in item
    ]
    critical_widgets = {
        "heapUtilizationPercent": round(max(heap_used_percent_values), 1) if heap_used_percent_values else None,
        "pendingExecuteRequests": sum(metric_number(item, "pendingUserRequestCount") for item in thread_pool_runtime),
        "activeJtaTransactions": sum(metric_number(item, "activeTransactionsTotalCount") for item in jta_transactions),
        "jmsPendingMessages": sum(metric_number(item, "messagesPendingCount") for item in jms_destinations),
        "jdbcWaiters": sum(metric_number(item, "waitingForConnectionCurrentCount") for item in jdbc_health) or total_waiting_connections,
        "inactiveDeployments": len(inactive_deployments),
        "currentOpenSockets": sum(metric_number(item, "currentOpenSocketCount") for item in socket_runtime),
        "workManagerPendingRequests": sum(metric_number(item, "pendingRequests") for item in work_managers),
        "executeQueueLength": sum(metric_number(item, "queueLength") for item in thread_pool_runtime),
        "jvmUptime": max([metric_number(item, "uptime") for item in jvm_runtime] or [0]),
    }

    return {
        "error": configuration_error,
        "expectedServers": server_names,
        "runningServers": len(servers),
        "missingServers": missing_servers,
        "servers": servers,
        "serverInventory": server_inventory,
        "serverInventoryCount": len(server_inventory),
        "serverInventoryCommand": "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/")) if oracle_home else "",
        "serverInventoryError": server_inventory_error,
        "deployments": deployments,
        "deploymentCommand": "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/")) if oracle_home else "",
        "deploymentConnectUrl": deployment_connect_url,
        "deploymentError": deployment_error,
        "deploymentCount": len(deployments),
        "activeDeploymentCount": len(active_deployments),
        "inactiveDeploymentCount": len(inactive_deployments),
        "stuckThreads": stuck_threads,
        "stuckThreadCommand": "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/")) if oracle_home else "",
        "stuckThreadError": stuck_thread_error,
        "stuckThreadCount": total_stuck_threads,
        "hoggingThreadCount": total_hogging_threads,
        "serversWithStuckThreads": servers_with_stuck_threads,
        "serversWithHoggingThreads": servers_with_hogging_threads,
        "jdbcPools": jdbc_pools,
        "jdbcPoolCommand": "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/")) if oracle_home else "",
        "jdbcPoolError": jdbc_pool_error,
        "jdbcPoolCount": len(jdbc_pools),
        "jdbcActiveConnectionCount": total_active_connections,
        "jdbcWaitingConnectionCount": total_waiting_connections,
        "runtimeMetricsCommand": "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/")) if oracle_home else "",
        "runtimeMetricsError": runtime_metrics_error,
        "jtaTransactions": jta_transactions,
        "jmsDestinations": jms_destinations,
        "jvmRuntime": jvm_runtime,
        "threadPoolRuntime": thread_pool_runtime,
        "jdbcHealth": jdbc_health,
        "socketRuntime": socket_runtime,
        "workManagers": work_managers,
        "criticalWidgets": critical_widgets,
    }


def get_oud_metrics(target, environment):
    if not (environment.get("products") or {}).get("oud"):
        return None

    settings = environment.get("oud") or {}
    instance_home = str(settings.get("instanceHome") or "").strip()
    bind_dn = settings.get("bindDn")
    bind_password = settings.get("bindPassword")
    status_path = str(settings.get("statusPath") or "").strip()
    bin_directory = "{0}/bin".format(instance_home.rstrip("/")) if instance_home else ""
    if not bin_directory and status_path and "/" in status_path:
        bin_directory = status_path.rsplit("/", 1)[0]
    if not bin_directory:
        return {
            "error": "OUD_INSTANCE_HOME Path is not configured.",
            "listeners": [],
            "backends": [],
            "commands": [],
        }

    status_command = 'cd {0} && pwfile=$(mktemp ./pwd.XXXXXX.txt) && trap \'rm -f "$pwfile"\' EXIT && printf %s {1} > "$pwfile" && chmod 600 "$pwfile" && ./status -D {2} -j "$pwfile"'.format(
        shlex.quote(bin_directory),
        shlex.quote(str(bind_password or "")),
        shlex.quote(str(bind_dn or "")),
    )
    replication_command = 'cd {0} && pwfile=$(mktemp ./pwd.XXXXXX.txt) && trap \'rm -f "$pwfile"\' EXIT && printf %s {1} > "$pwfile" && chmod 600 "$pwfile" && export COLUMNS=240 && ./dsreplication status -D {2} -j "$pwfile" -X --Advanced -n'.format(
        shlex.quote(bin_directory),
        shlex.quote(str(bind_password or "")),
        shlex.quote(str(bind_dn or "")),
    )
    build_command = "cd {0} && ./start-ds -F".format(shlex.quote(bin_directory))
    system_command = "cd {0} && ./start-ds -s".format(shlex.quote(bin_directory))

    errors = []
    status_output = ""
    replication_output = ""
    if bind_dn and bind_password:
        status_result = run_target(target, status_command)
        status_output = status_result.get("output")
        if status_result.get("exit_code") != 0:
            errors.append("status command failed: {0}".format(status_output or "unknown error"))
        replication_result = run_target(target, replication_command)
        replication_output = replication_result.get("output")
        if replication_result.get("exit_code") != 0:
            errors.append("dsreplication status failed: {0}".format(replication_output or "unknown error"))
    else:
        errors.append("OUD root user or password is not configured.")

    build_result = run_target(target, build_command)
    if build_result.get("exit_code") != 0:
        errors.append("start-ds -F failed: {0}".format(build_result.get("output") or "unknown error"))

    system_result = run_target(target, system_command)
    if system_result.get("exit_code") != 0:
        errors.append("start-ds -s failed: {0}".format(system_result.get("output") or "unknown error"))

    parsed = parse_oud_status(status_output)
    replication_sections = parse_oud_replication(replication_output)
    build_info = parse_key_value_banner_output(build_result.get("output"))
    system_info = parse_key_value_banner_output(system_result.get("output"))
    summary = parsed.get("summary") or {}
    backends = parsed.get("backends") or []
    open_connections = summary.get("Open Connections")
    system_values = system_info.get("values") or {}
    build_values = build_info.get("values") or {}
    db_directory = resolve_existing_directory(target, [
        "{0}/db".format(instance_home.rstrip("/")) if instance_home else "",
    ])
    changelog_db_directory = resolve_existing_directory(target, [
        "{0}/changelogDB".format(instance_home.rstrip("/")) if instance_home else "",
        "{0}/changelogDb".format(instance_home.rstrip("/")) if instance_home else "",
    ])
    schema_directory = resolve_existing_directory(target, [
        "{0}/config/schema".format(instance_home.rstrip("/")) if instance_home else "",
        "{0}/cnfig/schema".format(instance_home.rstrip("/")) if instance_home else "",
    ])
    db_size = directory_size_label(target, db_directory)
    changelog_db_size = directory_size_label(target, changelog_db_directory)
    custom_schema_files = schema_match_files(target, schema_directory)
    replication_nodes = []
    for section in replication_sections:
        for server_row in section.get("servers") or []:
            row = dict(server_row)
            row["baseDn"] = section.get("baseDn")
            row["replicationEnabled"] = bool(section.get("enabled"))
            replication_nodes.append(row)
    unique_replication_servers = sorted({
        str(row.get("server") or "").strip()
        for row in replication_nodes
        if str(row.get("server") or "").strip()
    })
    replication_enabled_sections = [section for section in replication_sections if section.get("enabled")]
    replication_disabled_sections = [section for section in replication_sections if not section.get("enabled")]

    def pretty_memory(key):
        raw_value = system_values.get(key)
        numeric = threshold_value(raw_value)
        return humanize_bytes(numeric) if numeric is not None else raw_value

    return {
        "error": "; ".join(errors) if errors else None,
        "binDirectory": bin_directory,
        "commands": [
            {"label": "OUD Status", "command": 'cd {0} && ./status -D "{1}" -j <temporary password file>'.format(bin_directory, bind_dn or "cn=Directory Manager")},
            {"label": "Replication Status", "command": 'cd {0} && ./dsreplication status -D "{1}" -j <temporary password file> -X --Advanced -n'.format(bin_directory, bind_dn or "cn=Directory Manager")},
            {"label": "Build Version", "command": "cd {0} && ./start-ds -F".format(bin_directory)},
            {"label": "Runtime System", "command": "cd {0} && ./start-ds -s".format(bin_directory)},
        ],
        "serverRunStatus": summary.get("Server Run Status"),
        "openConnections": int(open_connections) if open_connections and str(open_connections).isdigit() else open_connections,
        "hostName": summary.get("Host Name") or system_values.get("System Name"),
        "administrativeUsers": summary.get("Administrative Users") or bind_dn,
        "installationPath": summary.get("Installation Path") or system_values.get("Installation Directory"),
        "instancePath": summary.get("Instance Path") or system_values.get("Instance Directory") or instance_home,
        "dbSize": db_size,
        "changelogDbSize": changelog_db_size,
        "customSchemaPresent": bool(custom_schema_files),
        "customSchemaFiles": custom_schema_files,
        "customSchemaCount": len(custom_schema_files),
        "customSchemaDirectory": schema_directory or None,
        "version": summary.get("Version") or build_info.get("banner") or system_info.get("banner"),
        "javaVersion": summary.get("Java Version") or system_values.get("JAVA Version") or build_values.get("Build Java Version"),
        "administrationConnector": summary.get("Administration Connector"),
        "listeners": parsed.get("listeners") or [],
        "backends": backends,
        "namingContexts": [item.get("baseDn") for item in backends if item.get("baseDn")],
        "replicationSections": replication_sections,
        "replicationNodes": replication_nodes,
        "replicationEnabledCount": len(replication_enabled_sections),
        "replicationDisabledCount": len(replication_disabled_sections),
        "replicationNodeCount": len(unique_replication_servers),
        "replicationNodeNames": unique_replication_servers,
        "replicationConflictCount": sum(
            int(row.get("conflicts") or 0)
            for row in replication_nodes
            if str(row.get("conflicts") or "").isdigit()
        ),
        "replicationNormalCount": len([
            row for row in replication_nodes
            if str(row.get("status") or "").strip().lower() == "normal"
        ]),
        "buildId": build_values.get("Build ID"),
        "majorVersion": build_values.get("Major Version"),
        "maintenanceVersion": build_values.get("Maintenance Version"),
        "releaseVersion": build_values.get("Release Version"),
        "componentVersion": build_values.get("Component Version"),
        "platformVersion": build_values.get("Platform Version"),
        "patchVersion": build_values.get("Patch Version"),
        "labelIdentifier": build_values.get("Label Identifier"),
        "debugBuild": build_values.get("Debug Build"),
        "buildOs": build_values.get("Build OS"),
        "buildUser": build_values.get("Build User"),
        "buildJavaVersion": build_values.get("Build Java Version"),
        "buildJavaVendor": build_values.get("Build Java Vendor"),
        "buildJvmVersion": build_values.get("Build JVM Version"),
        "buildJvmVendor": build_values.get("Build JVM Vendor"),
        "jeVersion": system_values.get("JE Version"),
        "javaHome": system_values.get("JAVA Home"),
        "classPath": system_values.get("Class Path"),
        "operatingSystem": system_values.get("Operating System"),
        "jvmArchitecture": system_values.get("JVM Architecture"),
        "systemName": system_values.get("System Name"),
        "availableProcessors": system_values.get("Available Processors"),
        "maxAvailableMemory": pretty_memory("Max Available Memory"),
        "currentlyUsedMemory": pretty_memory("Currently Used Memory"),
        "currentlyFreeMemory": pretty_memory("Currently Free Memory"),
    }


def parse_json_payload(text):
    try:
        return json.loads(text or "")
    except (TypeError, ValueError):
        return None


def parse_kubernetes_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        candidates = [text[:-1], text]
    else:
        candidates = [re.sub(r"([+-]\d\d):?(\d\d)$", "", text)]
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        if "." in candidate:
            base, fraction = candidate.split(".", 1)
            fraction = re.sub(r"\D.*$", "", fraction)[:6]
            candidate = "{0}.{1}".format(base, fraction)
            formats = ["%Y-%m-%dT%H:%M:%S.%f"]
        else:
            formats = ["%Y-%m-%dT%H:%M:%S"]
        for date_format in formats:
            try:
                return datetime.strptime(candidate, date_format).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def kubernetes_age(created_at):
    created = parse_kubernetes_timestamp(created_at)
    if not created:
        return ""
    delta = datetime.now(timezone.utc) - created
    seconds = max(0, int(delta.total_seconds()))
    days = seconds // 86400
    if days:
        return "{0}d".format(days)
    hours = seconds // 3600
    if hours:
        return "{0}h".format(hours)
    minutes = seconds // 60
    if minutes:
        return "{0}m".format(minutes)
    return "{0}s".format(seconds)


def parse_kubernetes_pods(payload):
    rows = []
    for pod in (payload or {}).get("items") or []:
        metadata = pod.get("metadata") or {}
        status = pod.get("status") or {}
        spec = pod.get("spec") or {}
        containers = status.get("containerStatuses") or []
        total_containers = len(containers) or len(spec.get("containers") or [])
        ready_containers = len([item for item in containers if item.get("ready")])
        restarts = sum(int(item.get("restartCount") or 0) for item in containers)
        reason = status.get("reason") or status.get("phase") or ""
        waiting_reasons = [
            (((item.get("state") or {}).get("waiting") or {}).get("reason") or "")
            for item in containers
        ]
        waiting_reasons = [item for item in waiting_reasons if item]
        if waiting_reasons:
            reason = ", ".join(waiting_reasons)
        rows.append({
            "name": metadata.get("name") or "",
            "namespace": metadata.get("namespace") or "",
            "ready": "{0}/{1}".format(ready_containers, total_containers or ready_containers),
            "readyContainers": ready_containers,
            "totalContainers": total_containers,
            "status": reason,
            "restarts": restarts,
            "age": kubernetes_age(metadata.get("creationTimestamp")),
            "podIp": status.get("podIP") or "",
            "node": spec.get("nodeName") or "",
        })
    return rows


def format_kubernetes_ports(ports):
    formatted = []
    for port in ports or []:
        parts = []
        if port.get("port") is not None:
            parts.append(str(port.get("port")))
        if port.get("nodePort") is not None:
            parts.append(str(port.get("nodePort")))
        protocol = port.get("protocol") or ""
        if protocol:
            parts.append(protocol)
        if parts:
            formatted.append(":".join(parts))
    return ", ".join(formatted)


def parse_kubernetes_resources(payload):
    rows = []
    for item in (payload or {}).get("items") or []:
        metadata = item.get("metadata") or {}
        spec = item.get("spec") or {}
        status = item.get("status") or {}
        kind = item.get("kind") or ""
        name = metadata.get("name") or ""
        detail = ""
        endpoint = ""
        ready = ""
        if kind == "Service":
            detail = spec.get("type") or ""
            endpoint = "{0} {1}".format(spec.get("clusterIP") or "", format_kubernetes_ports(spec.get("ports") or [])).strip()
        elif kind == "Deployment":
            replicas = spec.get("replicas")
            ready_replicas = status.get("readyReplicas") or 0
            updated = status.get("updatedReplicas") or 0
            available = status.get("availableReplicas") or 0
            ready = "{0}/{1}".format(ready_replicas, replicas if replicas is not None else 0)
            detail = "updated {0}, available {1}".format(updated, available)
        elif kind == "ReplicaSet":
            ready = "{0}/{1}".format(status.get("readyReplicas") or 0, spec.get("replicas") or 0)
            detail = "current {0}".format(status.get("replicas") or 0)
        elif kind == "Pod":
            pod_rows = parse_kubernetes_pods({"items": [item]})
            if pod_rows:
                ready = pod_rows[0].get("ready") or ""
                detail = pod_rows[0].get("status") or ""
                endpoint = pod_rows[0].get("podIp") or ""
        elif kind == "Ingress":
            hosts = []
            for rule in spec.get("rules") or []:
                if rule.get("host"):
                    hosts.append(rule.get("host"))
            detail = ", ".join(hosts)
            load_balancers = status.get("loadBalancer", {}).get("ingress") or []
            endpoint = ", ".join([item.get("hostname") or item.get("ip") or "" for item in load_balancers if item])
        rows.append({
            "kind": kind,
            "name": name,
            "namespace": metadata.get("namespace") or "",
            "ready": ready,
            "detail": detail,
            "endpoint": endpoint,
            "age": kubernetes_age(metadata.get("creationTimestamp")),
        })
    return rows


def first_matching_pod(pods, release_name, purpose):
    names = [pod.get("name") for pod in pods if pod.get("name")]
    release = str(release_name or "").strip()
    preferred = []
    if purpose == "mgmt":
        preferred = ["{0}-oaa-mgmt".format(release), "oaa-mgmt", "oaamgmt"]
    elif purpose == "runtime":
        preferred = ["{0}-oaa-".format(release), "-oaa-"]
    for token in preferred:
        for name in names:
            if token and token in name:
                return name
    return names[0] if names else ""


def normalize_oaa_runtime_base_url(value):
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    marker = "/config/property/v1"
    if marker in text:
        text = text.split(marker, 1)[0]
    return text.rstrip("/")


def mask_oaa_property_value(name, value):
    text_name = str(name or "").lower()
    if any(token in text_name for token in ("password", "secret", "credential", "apikey", "api.key", "token")):
        return "******" if str(value or "").strip() else ""
    return value


def property_rows_from_json(value, parent_key=""):
    rows = []
    if isinstance(value, list):
        for item in value:
            rows.extend(property_rows_from_json(item, parent_key))
        return rows
    if isinstance(value, dict):
        if "items" in value:
            return property_rows_from_json(value.get("items"), parent_key)
        if "properties" in value:
            return property_rows_from_json(value.get("properties"), parent_key)
        name = value.get("propertyName") or value.get("name") or value.get("key")
        property_value = value.get("propertyValue")
        if property_value is None:
            property_value = value.get("value")
        if name:
            rows.append({"name": str(name), "value": mask_oaa_property_value(name, property_value)})
            return rows
        for key, item in value.items():
            child_name = "{0}.{1}".format(parent_key, key) if parent_key else str(key)
            if isinstance(item, (dict, list)):
                rows.extend(property_rows_from_json(item, child_name))
            else:
                rows.append({"name": child_name, "value": mask_oaa_property_value(child_name, item)})
    return rows


def parse_oaa_properties(text):
    payload = parse_json_payload(text)
    if payload is None:
        output = str(text or "").strip()
        return [{"name": "Raw Output", "value": output[:4000]}] if output else []
    return property_rows_from_json(payload)


def parse_oaa_deployment_details(text):
    details = []
    for raw_line in lines(text):
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if key.lower().endswith("apikey"):
            value = "******" if value else ""
        details.append({"name": key, "value": value})
    return details


def get_oaa_metrics(target, environment, progress=None):
    if not (environment.get("products") or {}).get("oaa"):
        return None

    settings = environment.get("oaa") or {}
    target = build_oaa_target(environment, target)
    namespace = str(settings.get("namespace") or "oaans").strip() or "oaans"
    ingress_namespace = str(settings.get("ingressNamespace") or "ingressns").strip() or "ingressns"
    release_name = str(settings.get("releaseName") or "oaainstall").strip() or "oaainstall"
    kubectl = str(settings.get("kubectlPath") or "kubectl").strip() or "kubectl"
    try:
        log_tail_lines = max(10, min(500, int(settings.get("logTailLines") or 80)))
    except (TypeError, ValueError):
        log_tail_lines = 80
    runtime_base_url = normalize_oaa_runtime_base_url(settings.get("runtimeBaseUrl"))
    runtime_username = str(settings.get("runtimeUsername") or "{0}-oaa".format(release_name)).strip()
    runtime_password = str(settings.get("runtimePassword") or "").strip()
    property_names = settings.get("propertyNames") or []
    errors = []

    if callable(progress):
        progress("Starting OAA Kubernetes collection for namespace {0}.".format(namespace))

    pods_command = "{0} get pods -n {1} -o json".format(shlex.quote(kubectl), shlex.quote(namespace))
    pods_result = run_target(target, pods_command, timeout=60)
    pods_payload = parse_json_payload(pods_result.get("output"))
    pods = parse_kubernetes_pods(pods_payload) if pods_payload else []
    pods_error = None
    if pods_result.get("exit_code") != 0:
        pods_error = pods_result.get("output") or "kubectl get pods failed."
        errors.append(pods_error)
    elif pods_payload is None:
        pods_error = "kubectl get pods did not return JSON."
        errors.append(pods_error)

    ingress_command = "{0} get all,ing -n {1} -o json".format(shlex.quote(kubectl), shlex.quote(ingress_namespace))
    ingress_result = run_target(target, ingress_command, timeout=60)
    ingress_payload = parse_json_payload(ingress_result.get("output"))
    ingress_resources = parse_kubernetes_resources(ingress_payload) if ingress_payload else []
    ingress_error = None
    if ingress_result.get("exit_code") != 0:
        ingress_error = ingress_result.get("output") or "kubectl get all,ing failed."
        errors.append(ingress_error)
    elif ingress_payload is None:
        ingress_error = "kubectl get all,ing did not return JSON."
        errors.append(ingress_error)

    describe_pod_name = first_matching_pod(pods, release_name, "runtime")
    describe_command = ""
    describe_output = ""
    describe_error = None
    if describe_pod_name:
        describe_command = "{0} describe pod {1} -n {2}".format(
            shlex.quote(kubectl),
            shlex.quote(describe_pod_name),
            shlex.quote(namespace),
        )
        describe_result = run_target(target, describe_command, timeout=60)
        describe_output = describe_result.get("output") or ""
        if describe_result.get("exit_code") != 0:
            describe_error = describe_output or "kubectl describe pod failed."

    log_command = ""
    log_output = ""
    log_error = None
    log_pod_name = describe_pod_name
    if log_pod_name:
        log_command = "{0} logs {1} -n {2} --tail={3}".format(
            shlex.quote(kubectl),
            shlex.quote(log_pod_name),
            shlex.quote(namespace),
            int(log_tail_lines),
        )
        log_result = run_target(target, log_command, timeout=60)
        log_output = log_result.get("output") or ""
        if log_result.get("exit_code") != 0:
            log_error = log_output or "kubectl logs failed."

    mgmt_pod_name = first_matching_pod(pods, release_name, "mgmt")
    deployment_details_command = ""
    deployment_details = []
    deployment_details_error = None
    if mgmt_pod_name:
        script_command = "cd ~/scripts && ./printOAADetails.sh -f settings/installOAA.properties"
        deployment_details_command = "{0} exec -n {1} {2} -- /bin/bash -lc {3}".format(
            shlex.quote(kubectl),
            shlex.quote(namespace),
            shlex.quote(mgmt_pod_name),
            shlex.quote(script_command),
        )
        deployment_result = run_target(target, deployment_details_command, timeout=90)
        deployment_details = parse_oaa_deployment_details(deployment_result.get("output"))
        if deployment_result.get("exit_code") != 0:
            deployment_details_error = deployment_result.get("output") or "printOAADetails.sh failed."
    elif pods:
        deployment_details_error = "OAA management pod was not found in namespace {0}.".format(namespace)

    property_command = ""
    properties = []
    properties_error = None
    specific_properties = []
    if runtime_base_url and runtime_username and runtime_password:
        all_property_url = "{0}/config/property/v1?propertyName=*".format(runtime_base_url)
        property_command = "curl -k --noproxy '*' -sS -u {0}:<password> -X GET {1}".format(
            shlex.quote(runtime_username),
            shlex.quote(all_property_url),
        )
        actual_property_command = "curl -k --noproxy '*' -sS -u {0}:{1} -X GET {2}".format(
            shlex.quote(runtime_username),
            shlex.quote(runtime_password),
            shlex.quote(all_property_url),
        )
        property_result = run_target(target, actual_property_command, timeout=60)
        property_output = property_result.get("output")
        property_payload = parse_json_payload(property_output)
        properties = property_rows_from_json(property_payload) if property_payload is not None else []
        if property_result.get("exit_code") != 0:
            properties_error = property_result.get("output") or "OAA property API request failed."
            errors.append(properties_error)
        elif property_payload is None:
            preview = (str(property_output or "").strip().splitlines() or [""])[0][:180]
            properties_error = "OAA property API did not return JSON."
            if preview:
                properties_error = "{0} First line: {1}".format(properties_error, preview)
            errors.append(properties_error)
        for property_name in property_names:
            name = str(property_name or "").strip()
            if not name:
                continue
            property_url = "{0}/config/property/v1?propertyName={1}".format(runtime_base_url, quote(name, safe=""))
            actual_specific_command = "curl -k --noproxy '*' -sS -u {0}:{1} -X GET {2}".format(
                shlex.quote(runtime_username),
                shlex.quote(runtime_password),
                shlex.quote(property_url),
            )
            specific_result = run_target(target, actual_specific_command, timeout=45)
            specific_output = specific_result.get("output")
            specific_payload = parse_json_payload(specific_output)
            rows = property_rows_from_json(specific_payload) if specific_payload is not None else []
            if rows:
                for row in rows:
                    item = dict(row)
                    item["requestedName"] = name
                    specific_properties.append(item)
            else:
                value = specific_output or ""
                if specific_payload is None and specific_result.get("exit_code") == 0:
                    value = "OAA property API did not return JSON."
                specific_properties.append({
                    "requestedName": name,
                    "name": name,
                    "value": value,
                    "error": specific_result.get("exit_code") != 0 or specific_payload is None,
                })
    else:
        missing = []
        if not runtime_base_url:
            missing.append("OAA Runtime Base URL")
        if not runtime_username:
            missing.append("OAA Runtime API Username")
        if not runtime_password:
            missing.append("OAA Runtime API Password")
        properties_error = "Missing OAA runtime property settings: {0}.".format(", ".join(missing))

    ready_pods = [pod for pod in pods if pod.get("readyContainers") == pod.get("totalContainers") and pod.get("status") == "Running"]
    running_pods = [pod for pod in pods if pod.get("status") == "Running"]
    restart_count = sum(int(pod.get("restarts") or 0) for pod in pods)

    return {
        "enabled": True,
        "namespace": namespace,
        "ingressNamespace": ingress_namespace,
        "releaseName": release_name,
        "error": "; ".join(errors) if errors else None,
        "commands": [
            {"label": "OAA Pods", "command": "{0} get pods -n {1}".format(kubectl, namespace)},
            {"label": "Ingress Resources", "command": "{0} get all,ing -n {1}".format(kubectl, ingress_namespace)},
            {"label": "OAA Properties", "command": property_command or "curl -k -u <runtime-user>:<password> <OAAService>/config/property/v1?propertyName=*"},
        ],
        "pods": pods,
        "podCount": len(pods),
        "readyPodCount": len(ready_pods),
        "runningPodCount": len(running_pods),
        "restartCount": restart_count,
        "podsCommand": pods_command,
        "podsError": pods_error,
        "ingressResources": ingress_resources,
        "ingressResourceCount": len(ingress_resources),
        "ingressCommand": ingress_command,
        "ingressError": ingress_error,
        "describePodName": describe_pod_name,
        "describeCommand": describe_command,
        "describeOutput": describe_output,
        "describeError": describe_error,
        "logPodName": log_pod_name,
        "logCommand": log_command,
        "logOutput": log_output,
        "logError": log_error,
        "managementPodName": mgmt_pod_name,
        "deploymentDetailsCommand": deployment_details_command,
        "deploymentDetails": deployment_details,
        "deploymentDetailsError": deployment_details_error,
        "runtimeBaseUrl": runtime_base_url,
        "runtimeUsername": runtime_username,
        "propertyCommand": property_command,
        "properties": properties[:250],
        "propertyCount": len(properties),
        "propertiesError": properties_error,
        "specificProperties": specific_properties,
        "specificPropertyNames": [str(item or "").strip() for item in property_names if str(item or "").strip()],
    }


def get_oig_metrics(environment, app_checks):
    if not (environment.get("products") or {}).get("oig"):
        return None

    oig_checks = [check for check in app_checks if check.get("product") == "oig"]
    if not oig_checks:
        return {
            "configured": False,
            "message": "OIG is enabled for this environment, but no OIG application checks are configured yet.",
        }

    return {
        "configured": True,
        "message": "OIG checks are configured and can be expanded with deeper runtime metrics later.",
        "checks": oig_checks,
    }


def get_product_metrics(target, environment, app_checks, progress=None):
    weblogic_metrics = None
    try:
        weblogic_metrics = get_weblogic_metrics(target, environment, progress=progress)
    except Exception as exc:
        weblogic_metrics = {
            "error": str(exc),
            "expectedServers": (environment.get("weblogic") or {}).get("serverNames") or [],
            "runningServers": 0,
            "missingServers": (environment.get("weblogic") or {}).get("serverNames") or [],
            "servers": [],
        }

    metrics = {
        "weblogic": weblogic_metrics,
        "oam": {
            "enabled": bool((environment.get("products") or {}).get("oam")),
            "runtime": weblogic_metrics,
            "message": "OAM runtime is derived from the WebLogic domain metrics on this environment.",
        } if (environment.get("products") or {}).get("oam") else None,
        "oud": None,
        "oaa": None,
        "oig": None,
    }

    try:
        metrics["oud"] = get_oud_metrics(target, environment)
    except Exception as exc:
        metrics["oud"] = {"error": str(exc), "listeners": [], "backends": []}

    try:
        metrics["oaa"] = get_oaa_metrics(target, environment, progress=progress)
    except Exception as exc:
        metrics["oaa"] = {"error": str(exc), "pods": [], "ingressResources": [], "properties": []}

    metrics["oig"] = get_oig_metrics(environment, app_checks)
    return metrics


def product_metrics_status(product_metrics):
    if not product_metrics:
        return "healthy"

    weblogic = product_metrics.get("weblogic") or {}
    if weblogic.get("error"):
        return "warning"
    if weblogic.get("deploymentError"):
        return "warning"

    expected_servers = weblogic.get("expectedServers") or []
    running_servers = weblogic.get("servers") or []
    missing_servers = weblogic.get("missingServers") or []
    if expected_servers and not running_servers:
        return "down"
    if missing_servers:
        return "warning"
    if (weblogic.get("inactiveDeploymentCount") or 0) > 0:
        return "warning"

    oud = product_metrics.get("oud") or {}
    if oud.get("error"):
        return "warning"

    if oud.get("serverRunStatus") and str(oud.get("serverRunStatus")).lower() != "started":
        return "down"

    listeners = oud.get("listeners") or []
    ldap_listeners = [listener for listener in listeners if listener.get("protocol") in ("LDAP", "LDAPS")]
    if ldap_listeners and any(listener.get("state") != "Enabled" for listener in ldap_listeners):
        return "warning"

    oaa = product_metrics.get("oaa") or {}
    if oaa.get("error"):
        return "warning"
    if oaa.get("podCount") and oaa.get("readyPodCount") != oaa.get("podCount"):
        return "warning"
    if oaa and oaa.get("podCount") == 0:
        return "down"

    return "healthy"


def combine_statuses(*statuses):
    normalized = [status for status in statuses if status]
    if "down" in normalized:
        return "down"
    if "warning" in normalized:
        return "warning"
    return "healthy"


def app_checks_status(app_checks):
    if not app_checks:
        return "healthy"
    healthy = len([item for item in app_checks if item["status"] == "healthy"])
    warning = len([item for item in app_checks if item["status"] == "warning"])
    if healthy == len(app_checks):
        return "healthy"
    if healthy > 0 or warning > 0:
        return "warning"
    return "warning"


def target_status(server, app_checks, product_metrics=None):
    if not server.get("reachable"):
        return "down"
    app_status = app_checks_status(app_checks)
    server_health_status = ((server.get("health") or {}).get("status")) or "healthy"
    if server_health_status == "critical":
        server_health_status = "warning"
    return combine_statuses(app_status, product_metrics_status(product_metrics), server_health_status)


def hydrate_dashboard_payload(dashboard_payload):
    dashboard_payload = dict(dashboard_payload or {})
    server = dict(dashboard_payload.get("server") or {})
    if server and not server.get("health"):
        server["health"] = build_server_health(server)
    dashboard_payload["server"] = server
    if server.get("reachable"):
        status = target_status(
            server,
            dashboard_payload.get("appChecks") or [],
            dashboard_payload.get("productMetrics") or {},
        )
        dashboard_payload["status"] = status
        server["status"] = status
    return dashboard_payload


def collect_monitoring_server(monitoring_config):
    target = build_monitoring_target(monitoring_config)
    snapshot = get_server_snapshot(
        target,
        script_directory=None,
        process_matchers=monitoring_config.get("processMatchers") or [],
    )
    status = "healthy" if snapshot.get("reachable") else "down"
    if snapshot.get("reachable"):
        snapshot["status"] = status
        snapshot["health"] = build_server_health(snapshot)

    return {
        "name": monitoring_config.get("name") or "IAM Monitoring Server",
        "host": monitoring_config.get("host") or "localhost",
        "description": monitoring_config.get("description") or "",
        "servicePort": monitoring_config.get("servicePort") or 8081,
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generatedAtLocal": time.strftime("%A, %B %d %Y %H:%M:%S %Z"),
        "status": status,
        "server": snapshot,
    }


def collect_environment_dashboard(environment, progress=None):
    target = build_environment_target(environment)
    server_metrics = environment.get("serverMetrics") or {}
    server = get_server_snapshot(
        target,
        script_directory=server_metrics.get("scriptDirectory"),
        process_matchers=server_metrics.get("processMatchers") or [],
    )
    server["health"] = build_server_health(server)
    app_checks = collect_app_checks(target, environment)
    product_metrics = get_product_metrics(target, environment, app_checks, progress=progress)
    status = target_status(server, app_checks, product_metrics)
    if server.get("reachable"):
        server["status"] = status

    return {
        "environment": {
            "id": environment.get("id"),
            "name": environment.get("name"),
            "description": environment.get("description"),
            "environmentType": environment.get("environmentType"),
            "products": environment.get("products") or {},
            "operations": environment.get("operations") or {},
            "collection": environment.get("collection") or {},
            "bootstrap": environment.get("bootstrap") or {},
            "server": {
                "host": (environment.get("server") or {}).get("host"),
                "port": (environment.get("server") or {}).get("port"),
                "username": (environment.get("server") or {}).get("username"),
                "sshMode": (environment.get("server") or {}).get("sshMode"),
                "authType": (environment.get("server") or {}).get("authType"),
                "sudoRequired": (environment.get("server") or {}).get("sudoRequired"),
            },
        },
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generatedAtLocal": time.strftime("%A, %B %d %Y %H:%M:%S %Z"),
        "status": status,
        "server": server,
        "appChecks": app_checks,
        "productMetrics": product_metrics,
        "summary": {
            "totalApps": len(app_checks),
            "healthyApps": len([item for item in app_checks if item["status"] == "healthy"]),
            "warningApps": len([item for item in app_checks if item["status"] == "warning"]),
            "downApps": len([item for item in app_checks if item["status"] == "down"]),
        },
        "notes": [
            "This environment uses the same SSH definition for monitoring, install, and upgrade workflows.",
            "Bootstrap uses the initial SSH access one time and then switches the environment to the installed runtime key for ongoing collection.",
            "Use Run Jobs Now when you want a fresh environment snapshot before the next scheduled collector window.",
        ],
    }


def build_environment_error_dashboard(environment, error_message):
    return {
        "environment": {
            "id": environment.get("id"),
            "name": environment.get("name"),
            "description": environment.get("description"),
            "environmentType": environment.get("environmentType"),
            "products": environment.get("products") or {},
            "operations": environment.get("operations") or {},
            "collection": environment.get("collection") or {},
            "bootstrap": environment.get("bootstrap") or {},
            "server": {
                "host": (environment.get("server") or {}).get("host"),
                "port": (environment.get("server") or {}).get("port"),
                "username": (environment.get("server") or {}).get("username"),
                "sshMode": (environment.get("server") or {}).get("sshMode"),
                "authType": (environment.get("server") or {}).get("authType"),
                "sudoRequired": (environment.get("server") or {}).get("sudoRequired"),
            },
        },
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generatedAtLocal": time.strftime("%A, %B %d %Y %H:%M:%S %Z"),
        "status": "down",
        "server": {
            "reachable": False,
            "status": "down",
            "actualHostname": None,
            "error": error_message,
            "health": {
                "status": "down",
                "checks": {},
                "thresholds": DEFAULT_SERVER_HEALTH_THRESHOLDS,
            },
        },
        "appChecks": [],
        "productMetrics": {},
        "summary": {
            "totalApps": 0,
            "healthyApps": 0,
            "warningApps": 0,
            "downApps": 0,
        },
        "notes": [
            "The environment could not be collected with the current connection settings.",
        ],
        "collectorError": error_message,
    }


def extract_environment_overview(dashboard_payload):
    dashboard_payload = hydrate_dashboard_payload(dashboard_payload)
    environment = dashboard_payload.get("environment") or {}
    server = dashboard_payload.get("server") or {}
    summary = dashboard_payload.get("summary") or {}
    return {
        "id": environment.get("id"),
        "name": environment.get("name"),
        "description": environment.get("description"),
        "host": (environment.get("server") or {}).get("host"),
        "status": dashboard_payload.get("status"),
        "generatedAt": dashboard_payload.get("generatedAt"),
        "generatedAtLocal": dashboard_payload.get("generatedAtLocal"),
        "generatedAtEpoch": dashboard_payload.get("generatedAtEpoch"),
        "actualHostname": server.get("actualHostname"),
        "environmentType": environment.get("environmentType"),
        "products": environment.get("products") or {},
        "sshMode": (environment.get("server") or {}).get("sshMode"),
        "authType": (environment.get("server") or {}).get("authType"),
        "summary": summary,
    }
