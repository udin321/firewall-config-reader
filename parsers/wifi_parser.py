import re


class WiFiParserMixin:

    def parse_fortiap_profiles(self) -> list:
        block = self._extract_block("wireless-controller wtp-profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            platform_m = re.search(r'set platform "?([^"\n]+)"?', body)
            rows.append({
                "Name":      name,
                "Platform":  platform_m.group(1) if platform_m else "-",
                "Comments":  g(r'set comment "([^"]+)"'),
            })
        return rows

    def parse_ssids(self) -> list:
        block = self._extract_block("wireless-controller vap")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":         name,
                "SSID":         g(r'set ssid "([^"]+)"'),
                "Traffic Mode": g(r'set vlanid (\d+)', "bridge").replace("bridge", "Bridge"),
                "Security":     g(r'set security (\S+)', "open").replace("-", " ").title(),
                "Schedule":     g(r'set schedule "([^"]+)"', "always"),
                "Status":       "Disable" if g(r'set status (\S+)') == "disable" else "Enable",
            })
        return rows

    def parse_managed_fortiaps(self) -> list:
        block = self._extract_block("wireless-controller wtp")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Access Point":    name,
                "Status":          g(r'set admin (\S+)', "enable").capitalize(),
                "Profile":         g(r'set wtp-profile "([^"]+)"'),
                "Location":        g(r'set location "([^"]+)"'),
                "Comments":        g(r'set comment "([^"]+)"'),
            })
        return rows

    def parse_wids_profiles(self) -> list:
        block = self._extract_block("wireless-controller wids-profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":             name,
                "Rogue AP Detection": g(r'set ap-scan (enable|disable)', "enable").capitalize(),
                "Comments":         g(r'set comment "([^"]+)"'),
            })
        return rows

    def parse_managed_switches(self) -> list:
        block = self._extract_block("switch-controller managed-switch")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":             name,
                "Switch Group":     g(r'set switch-group "([^"]+)"'),
                "Status":           g(r'set status (\S+)', "enable").capitalize(),
                "Model":            g(r'set platform (\S+)'),
                "Firmware Version": g(r'set firmware-provision-version "([^"]+)"'),
            })
        return rows

    def parse_switch_port_policies(self) -> list:
        block = self._extract_block("switch-controller port-policy")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":              name,
                "User Groups":       g(r'set user-group "([^"]+)"'),
                "Guest VLAN":        g(r'set guest-vlan (\S+)'),
                "Guest Auth Delay":  g(r'set guest-auth-delay (\d+)', "30"),
                "MAC Auth Bypass":   g(r'set mac-auth-bypass (enable|disable)', "disable").capitalize(),
                "EAP Pass Through":  g(r'set eap-passthru (enable|disable)', "disable").capitalize(),
                "Override RADIUS":   g(r'set radius-timeout-overwrite (enable|disable)', "disable").capitalize(),
            })
        return rows

    def parse_nac_policies(self) -> list:
        block = self._extract_block("switch-controller nac-settings")
        if not block:
            block = self._extract_block("user nac-policy")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":            name,
                "Patterns":        g(r'set hw-vendor "([^"]+)"'),
                "Assign":          g(r'set assign-vlan (\d+)'),
                "Matched Devices": g(r'set matched-devices (\d+)', "0"),
            })
        return rows
