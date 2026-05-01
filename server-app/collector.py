import re
import shlex
import subprocess
import time


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


def parse_oud_status(text):
    summary = {}
    listeners = []
    backends = []
    block = {}

    def flush_block():
        if not block:
            return
        if "Protocol" in block:
            listeners.append({
                "addressPort": block.get("Address:Port"),
                "protocol": block.get("Protocol"),
                "state": block.get("State"),
            })
        elif "Base DN" in block:
            entries_value = block.get("Entries")
            backends.append({
                "baseDn": block.get("Base DN"),
                "backendId": block.get("Backend ID"),
                "entries": int(entries_value) if entries_value and str(entries_value).isdigit() else entries_value,
                "replication": block.get("Replication"),
            })
        block.clear()

    for raw_line in lines(text):
        if raw_line == "-":
            flush_block()
            continue

        if raw_line.startswith("Address:Port:"):
            key = "Address:Port"
            value = raw_line[len("Address:Port:"):].strip()
        else:
            if ":" not in raw_line:
                continue
            key, value = raw_line.split(":", 1)
            key = key.strip()
            value = value.strip()

        if key in ("Address:Port", "Protocol", "State", "Base DN", "Backend ID", "Entries", "Replication"):
            block[key] = value
        else:
            flush_block()
            summary[key] = value

    flush_block()

    return {
        "summary": summary,
        "listeners": listeners,
        "backends": backends,
    }


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
    return {
        "mode": server.get("mode") or "ssh",
        "host": server.get("host") or "",
        "port": server.get("port") or 22,
        "username": server.get("username") or "root",
        "sshMode": server.get("sshMode") or "root_password",
        "authType": server.get("authType") or "password",
        "sudoRequired": bool(server.get("sudoRequired")),
        "password": server.get("password") or "",
        "privateKeyPath": server.get("privateKeyPath") or "",
        "passphrase": server.get("passphrase") or "",
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


def get_weblogic_metrics(target, environment):
    products = environment.get("products") or {}
    if not products.get("weblogic") and not products.get("oam"):
        return None

    settings = environment.get("weblogic") or {}
    server_names = settings.get("serverNames") or []
    jstat_path = settings.get("jstatPath")
    process_patterns = ["Dweblogic.Name={0}".format(name) for name in server_names] if server_names else ["Dweblogic.Name="]

    process_result = run_target(
        target,
        "ps -eo pid=,nlwp=,rss=,args= | egrep {0} | grep -v grep".format(shlex.quote("|".join(process_patterns))),
    )

    servers = []
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

    return {
        "expectedServers": server_names,
        "runningServers": len(servers),
        "missingServers": missing_servers,
        "servers": servers,
    }


def get_oud_metrics(target, environment):
    if not (environment.get("products") or {}).get("oud"):
        return None

    settings = environment.get("oud") or {}
    status_path = settings.get("statusPath")
    bind_dn = settings.get("bindDn")
    bind_password = settings.get("bindPassword") or (environment.get("server") or {}).get("password")
    if not status_path or not bind_dn or not bind_password:
        return {
            "error": "OUD status path or credentials are not configured.",
            "listeners": [],
            "backends": [],
        }

    command = (
        'pwfile=$(mktemp); '
        'trap \'rm -f "$pwfile"\' EXIT; '
        'printf %s {0} > "$pwfile"; '
        '{1} --bindDN {2} --bindPasswordFile "$pwfile" --trustAll --no-prompt --script-friendly'
    ).format(
        shlex.quote(bind_password),
        shlex.quote(status_path),
        shlex.quote(bind_dn),
    )

    status_result = run_target(target, command)
    parsed = parse_oud_status(status_result.get("output"))
    root = get_oud_root_dse(target, settings, bind_password)
    summary = parsed.get("summary") or {}
    open_connections = summary.get("Open Connections")

    return {
        "serverRunStatus": summary.get("Server Run Status"),
        "openConnections": int(open_connections) if open_connections and str(open_connections).isdigit() else open_connections,
        "hostName": summary.get("Host Name"),
        "administrativeUsers": summary.get("Administrative Users"),
        "installationPath": summary.get("Installation Path"),
        "instancePath": summary.get("Instance Path"),
        "version": summary.get("Version") or root.get("vendorVersion"),
        "javaVersion": summary.get("Java Version"),
        "administrationConnector": summary.get("Administration Connector"),
        "listeners": parsed.get("listeners") or [],
        "backends": parsed.get("backends") or [],
        "namingContexts": root.get("namingContexts") or [],
        "vendorName": root.get("vendorName"),
        "vendorVersion": root.get("vendorVersion"),
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

    expected_servers = weblogic.get("expectedServers") or []
    running_servers = weblogic.get("servers") or []
    missing_servers = weblogic.get("missingServers") or []
    if expected_servers and not running_servers:
        return "down"
    if missing_servers:
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
