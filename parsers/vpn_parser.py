import re


class VPNParserMixin:

    def parse_ipsec_phase1(self) -> list:
        block = self._extract_block("vpn ipsec phase1-interface")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(pattern, default="-"):
                m = re.search(pattern, body)
                return m.group(1).strip() if m else default

            rows.append({
                "name":         name,
                "interface":    g(r'set interface "([^"]+)"'),
                "comments":     g(r'set comments "([^"]+)"'),
                "status":       "Disable" if g(r'set disabled (enable|disable)') == "enable" else "Enable",
                "remote_gw":    g(r'set remote-gw ([\d\.]+)'),
                "peertype":     g(r'set peertype (\S+)'),
                "proposal":     g(r'set proposal (.*)'),
                "dhgrp":        g(r'set dhgrp (.*)'),
                "nattraversal": g(r'set nattraversal (\S+)', "enable"),
                "dpd":          g(r'set dpd (\S+)', "on-demand"),
                "dpd_retrycount":  g(r'set dpd-retrycount (\d+)', "3"),
                "dpd_retryinterval": g(r'set dpd-retryinterval (\d+)', "20"),
                "ike_version":  g(r'set ike-version (\d+)', "1"),
                "mode":         g(r'set mode (\S+)', "main"),
                "authmethod":   g(r'set authmethod (\S+)', "psk"),
                "keylifetime":  g(r'set keylifetime (\d+)', "86400"),
                "local_gw":     g(r'set local-gw ([\d\.]+)'),
                "mode_cfg":     g(r'set mode-cfg (enable|disable)', "disable"),
                "add_route":    g(r'set add-route (enable|disable)', "enable"),
                "auto_disc_sender":   g(r'set auto-discovery-sender (enable|disable)', "disable"),
                "auto_disc_receiver": g(r'set auto-discovery-receiver (enable|disable)', "disable"),
                "exchange_intf_ip":   g(r'set exchange-interface-ip (enable|disable)', "disable"),
                "dev_creation": g(r'set dev-creation (enable|disable)', "enable"),
                "net_device":   g(r'set net-device (enable|disable)', "disable"),
                "fec_egress":   g(r'set fec-egress (enable|disable)', "disable"),
                "fec_ingress":  g(r'set fec-ingress (enable|disable)', "disable"),
                "xauthtype":    g(r'set xauthtype (\S+)', "disable"),
                "localid":      g(r'set localid "?([^"\n]+)"?'),
                "ip_version":   g(r'set ip-version (\d+)', "4"),
            })
        return rows

    def parse_ipsec_phase2(self) -> list:
        block = self._extract_block("vpn ipsec phase2-interface")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(pattern, default="-"):
                m = re.search(pattern, body)
                return m.group(1).strip() if m else default

            rows.append({
                "name":           name,
                "phase1name":     g(r'set phase1name "([^"]+)"'),
                "comments":       g(r'set comments "([^"]+)"'),
                "proposal":       g(r'set proposal (.*)'),
                "dhgrp":          g(r'set dhgrp (.*)'),
                "pfs":            g(r'set pfs (enable|disable)', "enable"),
                "replay":         g(r'set replay (enable|disable)', "enable"),
                "auto_negotiate": g(r'set auto-negotiate (enable|disable)', "disable"),
                "keepalive":      g(r'set keepalive (enable|disable)', "disable"),
                "keylifetime":    g(r'set keylifetime-type (\S+)', "seconds"),
                "keylifeseconds": g(r'set keylifeseconds (\d+)', "43200"),
                "src_addr_type":  g(r'set src-addr-type (\S+)', "subnet"),
                "dst_addr_type":  g(r'set dst-addr-type (\S+)', "subnet"),
                "src_name":       g(r'set src-name "([^"]+)"'),
                "dst_name":       g(r'set dst-name "([^"]+)"'),
                "src_subnet":     g(r'set src-subnet ([\d\.\/\s]+)'),
                "dst_subnet":     g(r'set dst-subnet ([\d\.\/\s]+)'),
                "src_port":       g(r'set src-port (\d+)', "0"),
                "dst_port":       g(r'set dst-port (\d+)', "0"),
                "protocol":       g(r'set protocol (\d+)', "0"),
            })
        return rows

    def parse_ipsec_concentrator(self) -> list:
        block = self._extract_block("vpn ipsec concentrator")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            members = re.findall(r'set member "([^"]+)"', body)
            if not members:
                member_m = re.search(r'set member (.*)', body)
                if member_m:
                    members = re.findall(r'"([^"]+)"', member_m.group(1))
            rows.append({
                "Name":    name,
                "Members": ", ".join(members) if members else "-",
            })
        return rows

    def parse_ssl_portals(self) -> list:
        block = self._extract_block("vpn ssl web portal")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(pattern, default="-"):
                m = re.search(pattern, body)
                return m.group(1).strip() if m else default

            def flag(pattern, default="Disable"):
                m = re.search(pattern, body)
                return m.group(1).capitalize() if m else default

            # Split tunnel
            split_raw = g(r'set split-tunneling (\S+)', "disable")
            split_policy_m = re.search(r'set split-tunneling-routing-negate (enable|disable)', body)
            if split_raw == "disable":
                split_tunneling = "Disabled"
            elif split_policy_m and split_policy_m.group(1) == "enable":
                split_tunneling = "Enabled for Trusted Destinations"
            else:
                split_tunneling = "Enabled Based on Policy Destination"

            # IP pools
            ip_pools = re.findall(r'set ip-pools "([^"]+)"', body)

            # Bookmarks
            bookmarks = []
            bm_block = self._extract_sub_block(body, "bookmarks")
            if bm_block:
                for bm_entry in re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', bm_block, re.DOTALL | re.MULTILINE):
                    bm_name, bm_body = bm_entry
                    bm_type_m = re.search(r'set type (\S+)', bm_body)
                    bm_url_m  = re.search(r'set url "([^"]+)"', bm_body)
                    bm_desc_m = re.search(r'set description "([^"]+)"', bm_body)
                    bookmarks.append({
                        "Name":        bm_name,
                        "Type":        bm_type_m.group(1).upper() if bm_type_m else "-",
                        "Location":    bm_url_m.group(1) if bm_url_m else "-",
                        "Description": bm_desc_m.group(1) if bm_desc_m else "-",
                    })

            rows.append({
                "name":             name,
                "tunnel_mode":      flag(r'set tunnel-mode (enable|disable)'),
                "web_mode":         flag(r'set web-mode (enable|disable)'),
                "ipv6_tunnel":      flag(r'set ipv6-tunnel-mode (enable|disable)'),
                "split_tunneling":  split_tunneling,
                "ip_pools":         ", ".join(ip_pools) if ip_pools else "-",
                "one_user_limit":   flag(r'set limit-user-logins (enable|disable)'),
                "save_password":    flag(r'set allow-user-access save-password', "-"),
                "auto_connect":     flag(r'set auto-connect (enable|disable)'),
                "keep_alive":       flag(r'set keep-alive (enable|disable)'),
                "dns_split":        flag(r'set dns-split-tunneling (enable|disable)'),
                "host_check":       g(r'set host-check (\S+)', "none"),
                "portal_msg":       g(r'set portal-message "([^"]+)"'),
                "theme":            g(r'set theme "?([^"\n]+)"?'),
                "show_session_info": flag(r'set display-status (enable|disable)'),
                "show_launcher":    flag(r'set display-connection-tools (enable|disable)'),
                "show_history":     flag(r'set display-history (enable|disable)'),
                "user_bookmarks":   flag(r'set user-bookmarks (enable|disable)'),
                "rewrite_ip":       flag(r'set rewrite-ip-uri-ui (enable|disable)'),
                "clipboard":        flag(r'set rdp-clipboard (enable|disable)'),
                "forticlient_download": flag(r'set forticlient-download (enable|disable)'),
                "routing_override": g(r'set ip-pools "([^"]+)"'),
                "bookmarks":        bookmarks,
            })
        return rows

    def parse_ssl_settings(self) -> dict:
        block = self._extract_block("vpn ssl settings")
        if not block:
            return {}

        def g(pattern, default="-"):
            m = re.search(pattern, block)
            return m.group(1).strip() if m else default

        # Listen interfaces
        intf_list = re.findall(r'set source-interface "([^"]+)"', block)

        # Auth portal mapping
        auth_rules = []
        auth_block = self._extract_sub_block(block, "authentication-rule")
        if auth_block:
            for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', auth_block, re.DOTALL | re.MULTILINE):
                _, abody = entry
                users_m   = re.search(r'set users "([^"]+)"', abody)
                groups_m  = re.search(r'set groups "([^"]+)"', abody)
                portal_m  = re.search(r'set portal "([^"]+)"', abody)
                auth_rules.append({
                    "Users/Groups": users_m.group(1) if users_m else (groups_m.group(1) if groups_m else "All Other Users/Groups"),
                    "Portal":       portal_m.group(1) if portal_m else "Not Set",
                })

        # IP ranges
        ip_range = g(r'set tunnel-ip-pools "([^"]+)"')

        return {
            "enabled":          g(r'set status (enable|disable)', "enable"),
            "servercert":       g(r'set servercert "([^"]+)"', "Fortinet_Factory"),
            "port":             g(r'set port (\d+)', "443"),
            "http_redirect":    g(r'set http-redirect (enable|disable)', "disable"),
            "idle_timeout":     g(r'set idle-logout (\d+)', "300"),
            "require_cert":     g(r'set reqclientcert (enable|disable)', "disable"),
            "dtls_tunnel":      g(r'set dtls-tunnel (enable|disable)', "enable"),
            "restrict_access":  g(r'set source-address "([^"]+)"', "Allow Any"),
            "listen_interfaces": intf_list if intf_list else ["(default)"],
            "dns_server1":      g(r'set dns-server1 ([\d\.]+)'),
            "dns_server2":      g(r'set dns-server2 ([\d\.]+)'),
            "wins_server1":     g(r'set wins-server1 ([\d\.]+)'),
            "ip_range":         ip_range,
            "auth_rules":       auth_rules,
            "default_portal":   g(r'set default-portal "([^"]+)"', "full-access"),
        }

    def parse_ssl_clients(self) -> list:
        block = self._extract_block("vpn ssl client")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(pattern, default="-"):
                m = re.search(pattern, body)
                return m.group(1).strip() if m else default
            rows.append({
                "Tunnel":    name,
                "Interface": g(r'set interface "([^"]+)"'),
                "Server":    g(r'set server "([^"]+)"'),
                "Port":      g(r'set port (\d+)', "443"),
                "Comment":   g(r'set comment "([^"]+)"'),
            })
        return rows
