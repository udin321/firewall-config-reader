import re


class LOGSparserMixin:

    def __init__(self, raw: str):
        self.raw = raw

    # ─────────────────────────────
    # CORE BLOCK EXTRACTOR
    # ─────────────────────────────
    def _extract_block(self, keyword: str) -> str:

        lines = self.raw.splitlines()

        start = None
        depth = 0
        collected = []

        for line in lines:

            stripped = line.strip()

            if start is None and stripped.startswith(f"config {keyword}"):

                start = True

            if start is not None:

                collected.append(line)

                if stripped.startswith("config "):
                    depth += 1

                elif stripped == "end":

                    depth -= 1

                    if depth == 0:
                        break

        return "\n".join(collected)

    # ─────────────────────────────
    # LOG SETTINGS
    # ─────────────────────────────
    def parse_log_settings(self) -> dict:

        block = self._extract_block("log setting")

        mem_block = self._extract_block("log memory setting")

        syslog_block = self._extract_block("log null-device setting")

        def g(b, pattern, default="disable"):

            if not b:
                return default

            m = re.search(pattern, b, re.MULTILINE)

            return m.group(1).strip() if m else default

        return {
            # GLOBAL SETTINGS
            "fwpolicy_implicit_log": g(
                block, r"set fwpolicy-implicit-log (enable|disable)"
            ),
            "fwpolicy6_implicit_log": g(
                block, r"set fwpolicy6-implicit-log (enable|disable)"
            ),
            "local_in_allow": g(block, r"set local-in-allow (enable|disable)"),
            "local_in_deny_unicast": g(
                block, r"set local-in-deny-unicast (enable|disable)"
            ),
            "local_in_deny_broadcast": g(
                block, r"set local-in-deny-broadcast (enable|disable)"
            ),
            "local_out": g(block, r"set local-out (enable|disable)"),
            "daemon_log": g(block, r"set daemon-log (enable|disable)"),
            "neighbor_event": g(block, r"set neighbor-event (enable|disable)"),
            # GUI
            "resolve_ip": g(block, r"set resolve-ip (enable|disable)", "enable"),
            "resolve_port": g(block, r"set resolve-port (enable|disable)", "enable"),
            "log_user_in_upper": g(block, r"set user-anonymize (enable|disable)"),
            "syslog_override": g(block, r"set syslog-override (enable|disable)"),
            "faz_override": g(block, r"set faz-override (enable|disable)"),
            "brief_traffic_format": g(
                block, r"set brief-traffic-format (enable|disable)"
            ),
            "log_invalid_packet": g(block, r"set log-invalid-packet (enable|disable)"),
            # STORAGE
            "memory": g(mem_block, r"set status (enable|disable)"),
            "syslog": g(syslog_block, r"set status (enable|disable)"),
        }

    # ─────────────────────────────
    # MEMORY LOG
    # ─────────────────────────────
    def get_memory_log(self):

        block = self._extract_block("log memory setting")

        if not block:
            return {}

        def g(pattern, default=""):

            m = re.search(pattern, block)

            return m.group(1).strip() if m else default

        return {
            "status": g(r"set status (enable|disable)", "disable"),
            "diskfull": g(r"set diskfull (\S+)", "overwrite"),
        }

    # ─────────────────────────────
    # THREAT WEIGHT
    # ─────────────────────────────
    def parse_threat_weight(self):

        block = self._extract_block("log threat-weight")

        if not block:
            return {}

        LEVELS = {
            "off": "Off",
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "Critical",
        }

        def norm(v):

            return LEVELS.get(v.lower().strip(), "Medium")

        # ─────────────────────────
        # EXTRACT SECTION
        # ─────────────────────────
        def extract_section(name):

            lines = block.splitlines()

            collecting = False
            depth = 0

            data = []

            for line in lines:

                stripped = line.strip()

                if stripped.startswith(f"config {name}"):

                    collecting = True

                if collecting:

                    data.append(line)

                    if stripped.startswith("config "):
                        depth += 1

                    elif stripped == "end":

                        depth -= 1

                        if depth == 0:
                            break

            return "\n".join(data)

        # ─────────────────────────
        # WEB CATEGORY
        # ─────────────────────────
        web = {}

        web_block = extract_section("web")

        if web_block:

            entries = re.findall(r"edit\s+\d+(.*?)next", web_block, re.DOTALL)

            for entry in entries:

                cat = re.search(r"set category (\d+)", entry)

                lvl = re.search(r"set level (\w+)", entry)

                if cat:

                    category = cat.group(1)

                    level = norm(lvl.group(1)) if lvl else "Medium"

                    web[category] = level

        # ─────────────────────────
        # APPLICATION CATEGORY
        # ─────────────────────────
        application = {}

        app_block = extract_section("application")

        if app_block:

            entries = re.findall(r"edit\s+\d+(.*?)next", app_block, re.DOTALL)

            for entry in entries:

                cat = re.search(r"set category (\d+)", entry)

                lvl = re.search(r"set level (\w+)", entry)

                if cat:

                    category = cat.group(1)

                    level = norm(lvl.group(1)) if lvl else "Medium"

                    application[category] = level

        return {
            "status": "enable",
            # RISK VALUES
            "level": {
                "low": "5",
                "medium": "10",
                "high": "30",
                "critical": "50",
            },
            # IPS
            "ips_score": {
                "info": "off",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical",
            },
            # BOTNET
            "botnet_connection": "medium",
            # MALWARE
            "virus": "medium",
            "fortindr_virus": "medium",
            "fortisandbox_virus": "medium",
            "file_block": "medium",
            "command_block": "medium",
            "oversize": "medium",
            "virus_scan_error": "medium",
            "switch_proto": "medium",
            "mime_fragmented": "medium",
            "virus_file_type_executable": "medium",
            "outbreak_prevention": "medium",
            "cdn": "medium",
            "malware_list": "medium",
            "ems_threat_feed": "medium",
            "fortisandbox_malicious": "medium",
            "fortisandbox_high_risk": "medium",
            "fortisandbox_medium_risk": "medium",
            # PACKET
            "blocked_connection": "medium",
            "failed_connection": "medium",
            "url_block_detect": "medium",
            # WEB + APPLICATION
            "web": web,
            "application": application,
        }

    # ─────────────────────────────
    # ALIAS FOR VIEW
    # ─────────────────────────────
    def get_threat_weight(self):

        return self.parse_threat_weight()
