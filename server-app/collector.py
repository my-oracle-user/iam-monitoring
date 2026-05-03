import re
import shlex
import subprocess
import time
from urllib.parse import urlparse


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


def run_local(command):
    try:
        process = subprocess.Popen(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        output, _ = process.communicate(timeout=25)
        return {"exit_code": process.returncode, "output": (output or "").strip()}
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        return {"exit_code": 1, "output": ((output or "").strip() or "Local command timed out.")}


def run_ssh(target, command):
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
            timeout=25,
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


def run_target(target, command):
    if target.get("mode") == "local":
        return run_local(command)
    return run_ssh(target, command)


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
    server = environment.get("server") or {}
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


def run_wlst_script(target, wlst_path, script_body):
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
    return command, run_target(target, command)


def weblogic_profile_configured(environment):
    weblogic = environment.get("weblogic") or {}
    admin_host = weblogic.get("adminHost") or {}
    return bool(
        (environment.get("products") or {}).get("weblogic")
        or (environment.get("products") or {}).get("oam")
        or weblogic.get("enabled")
        or str(weblogic.get("adminUrl") or "").strip()
        or str(weblogic.get("oracleHome") or "").strip()
        or str(admin_host.get("host") or "").strip()
    )


def get_weblogic_metrics(target, environment):
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
    configuration_error = None
    weblogic_ready = bool(oracle_home and admin_username and admin_password and deployment_connect_url)

    if weblogic_ready:
        wlst_path = "{0}/oracle_common/common/bin/wlst.sh".format(oracle_home.rstrip("/"))
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
        if inventory_result.get("exit_code") != 0 and not server_inventory:
            server_inventory_error = inventory_result.get("output") or "WLST server inventory command failed."

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
        if deployment_result.get("exit_code") != 0 and not deployments:
            deployment_error = deployment_result.get("output") or "WLST deployment status command failed."
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


def get_product_metrics(target, environment, app_checks):
    weblogic_metrics = None
    try:
        weblogic_metrics = get_weblogic_metrics(target, environment)
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
        "oig": None,
    }

    try:
        metrics["oud"] = get_oud_metrics(target, environment)
    except Exception as exc:
        metrics["oud"] = {"error": str(exc), "listeners": [], "backends": []}

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


def collect_environment_dashboard(environment):
    target = build_environment_target(environment)
    server_metrics = environment.get("serverMetrics") or {}
    server = get_server_snapshot(
        target,
        script_directory=server_metrics.get("scriptDirectory"),
        process_matchers=server_metrics.get("processMatchers") or [],
    )
    server["health"] = build_server_health(server)
    app_checks = collect_app_checks(target, environment)
    product_metrics = get_product_metrics(target, environment, app_checks)
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
