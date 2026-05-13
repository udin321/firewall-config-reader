import re


class UserParserMixin:

    def parse_user_local(self) -> list:
        block = self._extract_block("user local")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            type_m   = re.search(r'set type (\S+)', body)
            twofactor_m = re.search(r'set two-factor (\S+)', body)
            status_m = re.search(r'set status (\S+)', body)
            email_m  = re.search(r'set email-to "([^"]+)"', body)
            rows.append({
                "Name":   name,
                "Type":   type_m.group(1).capitalize() if type_m else "Password",
                "2FA":    twofactor_m.group(1).capitalize() if twofactor_m else "Disable",
                "Email":  email_m.group(1) if email_m else "-",
                "Status": status_m.group(1).capitalize() if status_m else "Enable",
            })
        return rows

    def parse_user_groups(self) -> list:
        block = self._extract_block("user group")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            type_m   = re.search(r'set group-type (\S+)', body)
            member_m = re.search(r'set member (.*)', body)
            members  = ", ".join(re.findall(r'"([^"]+)"', member_m.group(1))) if member_m else "-"
            # Match rules for FSSO/LDAP
            match_groups = re.findall(r'set group-name "([^"]+)"', body)
            rows.append({
                "Group Name": name,
                "Group Type": type_m.group(1).upper() if type_m else "Firewall",
                "Members":    members,
                "Match Groups": ", ".join(match_groups) if match_groups else "-",
            })
        return rows

    def parse_ldap(self) -> list:
        block = self._extract_block("user ldap")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":        name,
                "Server IP":   g(r'set server "([^"]+)"'),
                "Port":        g(r'set port (\d+)', "389"),
                "Common Name": g(r'set cnid "([^"]+)"'),
                "DN":          g(r'set dn "([^"]+)"'),
                "Bind Type":   g(r'set type (\S+)', "simple").capitalize(),
                "Username":    g(r'set username "([^"]+)"'),
            })
        return rows

    def parse_radius(self) -> list:
        block = self._extract_block("user radius")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":        name,
                "Server":      g(r'set server "([^"]+)"'),
                "Port":        g(r'set auth-port (\d+)', "1812"),
                "Auth Method": g(r'set auth-type (\S+)', "auto").upper(),
            })
        return rows

    def parse_fsso(self) -> list:
        block = self._extract_block("user fsso")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            rows.append({
                "Name":      name,
                "Server":    g(r'set server "([^"]+)"'),
                "Port":      g(r'set port (\d+)', "8000"),
                "Source IP": g(r'set source-ip ([\d\.]+)'),
                "Type":      "FSSO Agent",
            })
        return rows

    def parse_fortitoken(self) -> list:
        block = self._extract_block("user fortitoken")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            token_type = "Mobile" if name.startswith("FTKMOB") else "Hardware"
            rows.append({
                "Serial Number": name,
                "Type":          token_type,
                "License":       g(r'set license "([^"]+)"'),
                "Status":        g(r'set status (\S+)', "active").capitalize(),
                "Comments":      g(r'set comments "([^"]+)"'),
            })
        return rows

    def parse_auth_settings(self) -> dict:
        block = self._extract_block("user setting")
        if not block:
            return {}
        def g(p, d="-"):
            m = re.search(p, block)
            return m.group(1).strip() if m else d
        return {
            "auth_cert":     g(r'set auth-cert "([^"]+)"'),
            "auth_timeout":  g(r'set auth-timeout (\d+)', "5"),
            "auth_type":     g(r'set auth-type (.*)', "http https"),
            "http_redirect": g(r'set auth-http-basic (enable|disable)', "disable"),
        }

    def parse_guest_users(self) -> list:
        block = self._extract_block("user group")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for grp_name, grp_body in entries:
            guest_block = self._extract_sub_block(grp_body, "guest")
            if not guest_block:
                continue
            for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', guest_block, re.DOTALL | re.MULTILINE):
                _, gbody = entry
                def g(p, d="-"):
                    m = re.search(p, gbody)
                    return m.group(1).strip() if m else d
                rows.append({
                    "User ID":  g(r'set user-id "([^"]+)"'),
                    "Name":     g(r'set name "([^"]+)"'),
                    "Expires":  g(r'set expiration "([^"]+)"'),
                    "Group":    grp_name,
                    "Comments": g(r'set comments "([^"]+)"'),
                })
        return rows
