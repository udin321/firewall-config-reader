import re

FTGD_CATEGORIES = {
    "1": "Drug Abuse", "2": "Pornography", "3": "Weapons",
    "4": "Violence", "5": "Racism/Hate", "6": "Phishing/Fraud",
    "7": "Gambling", "8": "Explicit Violence", "9": "Extremist Groups",
    "11": "Child Abuse", "12": "Proxy Avoidance", "13": "Hacking",
    "14": "Spyware/Malware", "15": "Copyright Infringement",
    "16": "Explicit Sexual Content", "17": "Entertainment",
    "18": "Education", "19": "Finance/Banking", "20": "News/Media",
    "23": "Shopping", "24": "Social Networking", "25": "Travel",
    "26": "Nudity", "28": "Sports", "29": "Games",
    "30": "Business/Economy", "31": "General Interest",
    "33": "Government/Legal", "34": "Health/Wellness",
    "35": "Hobbies/Recreation", "36": "Information Technology",
    "37": "Job Search", "38": "Kids/Minors", "39": "Personal Websites",
    "40": "Search Engines", "41": "Streaming Media",
    "42": "Translators", "43": "Web Ads", "44": "Web Mail",
    "46": "Forum/Bulletin Boards", "47": "Instant Messaging",
    "48": "IRC", "49": "Peer-to-Peer", "50": "Online Storage",
    "51": "VoIP", "52": "Remote Access", "53": "Bypass",
    "54": "Cryptocurrency", "55": "Artificial Intelligence",
    "56": "Greeting Cards", "57": "Sex Education",
    "58": "Plagiarism", "59": "Charitable Organizations",
    "61": "Lingerie/Swimsuit", "62": "Marijuana",
    "63": "Alcohol/Tobacco", "64": "Abused Drugs",
    "65": "Military/War", "66": "Criminal Activities",
    "67": "Cult/Occult", "68": "Dynamic DNS",
    "69": "File Sharing", "70": "Freeware/Software Downloads",
    "71": "Auctions", "72": "Real Estate",
    "75": "Restaurants/Dining", "76": "Motor Vehicles",
    "77": "Miscellaneous", "78": "Web Hosting",
    "79": "Arts/Culture", "80": "Brokerage/Trading",
    "81": "Abortion", "82": "Home/Garden",
    "83": "Anonymizers", "84": "Medicine",
    "85": "Fashion/Beauty", "86": "Adult Materials",
    "87": "Controversial Opinions", "88": "Dating/Personals",
    "89": "Closed Communities", "90": "Swimsuits/Lingerie",
    "91": "Intimate Apparel", "92": "Martial Arts",
    "93": "Hunting/Fishing", "94": "Tobacco",
    "95": "Alcohol", "96": "Terrorism",
}

WAF_CLASS_NAMES = {
    "100000000": "Known Exploits",
    "20000000":  "HTTP Request Limit",
    "30000000":  "HTTP Request Smuggling",
    "40000000":  "Cross-Site Scripting (XSS)",
    "50000000":  "SQL Injection",
    "60000000":  "Generic Attacks",
    "70000000":  "CSRF",
    "80000000":  "Protocol Enforcement",
    "90000000":  "Bot Mitigation",
    "110000000": "Information Disclosure",
}


def _depth_extract(text, keyword):
    marker = f"config {keyword}"
    start = text.find(marker)
    if start == -1:
        return ""
    depth = 0
    lines = text[start:].splitlines()
    collected = []
    for line in lines:
        stripped = line.strip()
        collected.append(line)
        if stripped.startswith("config "):
            depth += 1
        elif stripped == "end":
            depth -= 1
            if depth == 0:
                break
    return "\n".join(collected)


class SecurityProfileMixin:

    def _parse_urlfilter_tables(self) -> dict:
        """Parse webfilter urlfilter blocks, return dict keyed by table ID."""
        block = self._extract_block("webfilter urlfilter")
        if not block:
            return {}
        tables = {}
        entries = re.findall(r'^\s*edit (\d+)(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for table_id, body in entries:
            name_m = re.search(r'set name "([^"]+)"', body)
            entries_sub = _depth_extract(body, "entries")
            urls = []
            if entries_sub:
                for entry in re.findall(r'^\s*edit \d+(.*?)^\s*next', entries_sub, re.DOTALL | re.MULTILINE):
                    url_m    = re.search(r'set url "([^"]+)"', entry)
                    type_m   = re.search(r'set type (\S+)', entry)
                    action_m = re.search(r'set action (\S+)', entry)
                    status_m = re.search(r'set status (enable|disable)', entry)
                    if url_m:
                        urls.append({
                            "URL":    url_m.group(1),
                            "Type":   type_m.group(1).capitalize() if type_m else "Simple",
                            "Action": action_m.group(1).capitalize() if action_m else "Allow",
                            "Status": status_m.group(1).capitalize() if status_m else "Enable",
                        })
            tables[table_id] = {
                "name": name_m.group(1) if name_m else f"Table {table_id}",
                "urls": urls,
            }
        return tables

    def parse_antivirus(self) -> list:
        block = self._extract_block("antivirus profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m    = re.search(r'set comment "([^"]+)"', body)
            feature_m    = re.search(r'set feature-set (\S+)', body)
            feature_set  = feature_m.group(1) if feature_m else "flow"  # default flow-based
            protocols = []
            for proto in ["http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "ssh"]:
                sub = self._extract_sub_block(body, proto)
                if sub:
                    scan_m    = re.search(r'set av-scan (\S+)', sub)
                    exec_m    = re.search(r'set executables (\S+)', sub)
                    archive_m = re.search(r'set archive-block (.*)', sub)
                    protocols.append({
                        "Protocol":      proto.upper(),
                        "AV Scan":       scan_m.group(1).capitalize() if scan_m else "-",
                        "Executables":   exec_m.group(1).capitalize() if exec_m else "-",
                        "Archive Block": archive_m.group(1).strip() if archive_m else "-",
                    })
            rows.append({
                "name":        name,
                "comment":     comment_m.group(1) if comment_m else "-",
                "feature_set": feature_set,
                "protocols":   protocols,
            })
        return rows

    def parse_webfilter(self) -> list:
        block = self._extract_block("webfilter profile")
        if not block:
            return []
        url_tables = self._parse_urlfilter_tables()
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m    = re.search(r'set comment "([^"]+)"', body)
            safe_m       = re.search(r'set safe-search (enable|disable)', body)
            override_m   = re.search(r'set override (enable|disable)', body)
            options_m    = re.search(r'set options (.*)', body)
            feature_m    = re.search(r'set feature-set (\S+)', body)
            block_inv_m  = re.search(r'set block-invalid-url (enable|disable)', body)

            web_sub = self._extract_sub_block(body, "web")
            urlfilter_table_id = "-"
            block_invalid = block_inv_m.group(1) if block_inv_m else "disable"
            if web_sub:
                uf_m = re.search(r'set urlfilter-table (\d+)', web_sub)
                if uf_m:
                    urlfilter_table_id = uf_m.group(1)
                bi_m = re.search(r'set block-invalid-url (enable|disable)', web_sub)
                if bi_m:
                    block_invalid = bi_m.group(1)

            # Also check top-level options for block-invalid-url
            if options_m and "block-invalid-url" in options_m.group(1):
                block_invalid = "enable"

            # Resolve URL filter table name and entries
            url_filter_data = None
            if urlfilter_table_id != "-" and urlfilter_table_id in url_tables:
                url_filter_data = url_tables[urlfilter_table_id]

            categories = []
            ftgd_sub = _depth_extract(body, "ftgd-wf")
            if ftgd_sub:
                filter_sub = _depth_extract(ftgd_sub, "filters")
                if filter_sub:
                    for entry in re.findall(r'^\s*edit \d+(.*?)^\s*next', filter_sub, re.DOTALL | re.MULTILINE):
                        cat_m    = re.search(r'set category (\d+)', entry)
                        action_m = re.search(r'set action (\S+)', entry)
                        if cat_m:
                            cat_id = cat_m.group(1)
                            categories.append({
                                "Category ID":   cat_id,
                                "Category Name": FTGD_CATEGORIES.get(cat_id, f"Category {cat_id}"),
                                "Action":        action_m.group(1).capitalize() if action_m else "Monitor",
                            })
            rows.append({
                "name":              name,
                "comment":           comment_m.group(1) if comment_m else "-",
                "feature_set":       feature_m.group(1) if feature_m else "flow",
                "urlfilter_table":   urlfilter_table_id,
                "urlfilter_name":    url_filter_data["name"] if url_filter_data else "-",
                "urlfilter_entries": url_filter_data["urls"] if url_filter_data else [],
                "block_invalid_url": block_invalid,
                "safe_search":       safe_m.group(1).capitalize() if safe_m else "-",
                "override":          override_m.group(1).capitalize() if override_m else "-",
                "options":           options_m.group(1).strip() if options_m else "-",
                "categories":        categories,
            })
        return rows

    def parse_dnsfilter(self) -> list:
        block = self._extract_block("dnsfilter profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m  = re.search(r'set comment "([^"]+)"', body)
            block_bt_m = re.search(r'set block-botnet (enable|disable)', body)
            safe_m     = re.search(r'set safe-search (enable|disable)', body)
            feature_m  = re.search(r'set feature-set (\S+)', body)
            categories = []
            ftgd_sub = _depth_extract(body, "ftgd-dns")
            if ftgd_sub:
                filter_sub = _depth_extract(ftgd_sub, "filters")
                if filter_sub:
                    for entry in re.findall(r'^\s*edit \d+(.*?)^\s*next', filter_sub, re.DOTALL | re.MULTILINE):
                        cat_m    = re.search(r'set category (\d+)', entry)
                        action_m = re.search(r'set action (\S+)', entry)
                        if cat_m:
                            cat_id = cat_m.group(1)
                            categories.append({
                                "Category ID":   cat_id,
                                "Category Name": FTGD_CATEGORIES.get(cat_id, f"Category {cat_id}"),
                                "Action":        action_m.group(1).capitalize() if action_m else "Block",
                            })
            rows.append({
                "name":         name,
                "comment":      comment_m.group(1) if comment_m else "-",
                "feature_set":  feature_m.group(1) if feature_m else "flow",
                "block_botnet": block_bt_m.group(1).capitalize() if block_bt_m else "-",
                "safe_search":  safe_m.group(1).capitalize() if safe_m else "-",
                "categories":   categories,
            })
        return rows

    def parse_appcontrol(self) -> list:
        block = self._extract_block("application list")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m        = re.search(r'set comment "([^"]+)"', body)
            options_m        = re.search(r'set options (.*)', body)
            deep_m           = re.search(r'set deep-app-inspection (enable|disable)', body)
            unknown_action_m = re.search(r'set unknown-application-action (\S+)', body)
            entries_sub      = self._extract_sub_block(body, "entries")
            app_entries = []
            if entries_sub:
                for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', entries_sub, re.DOTALL | re.MULTILINE):
                    seq, ebody = entry
                    app_m    = re.search(r'set application ([\d ]+)', ebody)
                    cat_m    = re.search(r'set category ([\d ]+)', ebody)
                    action_m = re.search(r'set action (\S+)', ebody)
                    log_m    = re.search(r'set log (enable|disable)', ebody)
                    # Determine type and details
                    if app_m and app_m.group(1).strip() != "":
                        entry_type   = "Application"
                        details      = f"App ID: {app_m.group(1).strip()}"
                    elif cat_m and cat_m.group(1).strip() != "":
                        entry_type   = "Category"
                        details      = f"Cat ID: {cat_m.group(1).strip()}"
                    else:
                        entry_type   = "All"
                        details      = "All traffic"
                    app_entries.append({
                        "Priority": seq,
                        "Details":  details,
                        "Type":     entry_type,
                        "Action":   action_m.group(1).capitalize() if action_m else "Monitor",
                        "Log":      log_m.group(1).capitalize() if log_m else "Enable",
                    })
            rows.append({
                "name":           name,
                "comment":        comment_m.group(1) if comment_m else "-",
                "options":        options_m.group(1).strip() if options_m else "-",
                "deep_inspection": deep_m.group(1).capitalize() if deep_m else "Enable",
                "unknown_action": unknown_action_m.group(1).capitalize() if unknown_action_m else "-",
                "entries":        app_entries,
            })
        return rows

    def parse_ips(self) -> list:
        block = self._extract_block("ips sensor")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            block_m   = re.search(r'set block-malicious-url (enable|disable)', body)
            entries_sub = self._extract_sub_block(body, "entries")
            ips_entries = []
            if entries_sub:
                for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', entries_sub, re.DOTALL | re.MULTILINE):
                    seq, ebody = entry
                    sev_m    = re.search(r'set severity (.*)', ebody)
                    action_m = re.search(r'set action (\S+)', ebody)
                    proto_m  = re.search(r'set protocol (\S+)', ebody)
                    os_m     = re.search(r'set os (.*)', ebody)
                    app_m    = re.search(r'set application (.*)', ebody)
                    cve_m    = re.search(r'set cve (.*)', ebody)
                    sev_val  = sev_m.group(1).strip() if sev_m else "all"
                    ips_entries.append({
                        "Seq":       seq,
                        "Severity":  sev_val if sev_val else "all",
                        "Action":    action_m.group(1).capitalize() if action_m else "Default",
                        "Protocol":  proto_m.group(1) if proto_m else "all",
                        "OS":        os_m.group(1).strip() if os_m else "all",
                        "App":       app_m.group(1).strip() if app_m else "-",
                        "CVE":       cve_m.group(1).strip() if cve_m else "-",
                    })
            rows.append({
                "name":                name,
                "comment":             comment_m.group(1) if comment_m else "-",
                "block_malicious_url": block_m.group(1).capitalize() if block_m else "-",
                "entries":             ips_entries,
            })
        return rows

    def parse_filefilter(self) -> list:
        block = self._extract_block("file-filter profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            feature_m = re.search(r'set feature-set (\S+)', body)
            rules_sub = self._extract_sub_block(body, "rules")
            rules = []
            if rules_sub:
                for entry in re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', rules_sub, re.DOTALL | re.MULTILINE):
                    rname, rbody = entry
                    action_m    = re.search(r'set action (\S+)', rbody)
                    proto_m     = re.search(r'set protocol (.*)', rbody)
                    filetypes_m = re.search(r'set file-type (.*)', rbody)
                    rules.append({
                        "Rule":       rname,
                        "Action":     action_m.group(1).capitalize() if action_m else "-",
                        "Protocol":   proto_m.group(1).strip() if proto_m else "all",
                        "File Types": filetypes_m.group(1).strip() if filetypes_m else "-",
                    })
            rows.append({
                "name":        name,
                "comment":     comment_m.group(1) if comment_m else "-",
                "feature_set": feature_m.group(1) if feature_m else "flow",
                "rules":       rules,
            })
        return rows

    def parse_emailfilter(self) -> list:
        block = self._extract_block("emailfilter profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            spam_m    = re.search(r'set spam-filtering (enable|disable)', body)
            feature_m = re.search(r'set feature-set (\S+)', body)
            spam_bwl_m = re.search(r'set spam-bwl-table (\d+)', body)
            protocols = []
            for proto in ["imap", "pop3", "smtp"]:
                sub = self._extract_sub_block(body, proto)
                if sub:
                    log_m      = re.search(r'set log (enable|disable)', sub)
                    action_m   = re.search(r'set action (\S+)', sub)
                    tag_m      = re.search(r'set tag-msg "([^"]+)"', sub)
                    tag_type_m = re.search(r'set tag-type (.*)', sub)
                    protocols.append({
                        "Protocol": proto.upper(),
                        "Log":      log_m.group(1).capitalize() if log_m else "-",
                        "Action":   action_m.group(1).capitalize() if action_m else "-",
                        "Tag Msg":  tag_m.group(1) if tag_m else "-",
                        "Tag Type": tag_type_m.group(1).strip() if tag_type_m else "-",
                    })
            rows.append({
                "name":           name,
                "comment":        comment_m.group(1) if comment_m else "-",
                "feature_set":    feature_m.group(1) if feature_m else "flow",
                "spam_filtering": spam_m.group(1).capitalize() if spam_m else "-",
                "spam_bwl_table": spam_bwl_m.group(1) if spam_bwl_m else "-",
                "protocols":      protocols,
            })
        return rows

    def parse_voip(self) -> list:
        block = self._extract_block("voip profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m   = re.search(r'set comment "([^"]+)"', body)
            sip_sub     = self._extract_sub_block(body, "sip")
            sccp_sub    = self._extract_sub_block(body, "sccp")
            sip_config  = {}
            sccp_config = {}
            if sip_sub:
                rtp_m    = re.search(r'set rtp (enable|disable)', sip_sub)
                status_m = re.search(r'set status (enable|disable)', sip_sub)
                port_m   = re.search(r'set port (\d+)', sip_sub)
                sip_config = {
                    "status": status_m.group(1).capitalize() if status_m else "-",
                    "rtp":    rtp_m.group(1).capitalize() if rtp_m else "-",
                    "port":   port_m.group(1) if port_m else "5060",
                }
            if sccp_sub:
                status_m = re.search(r'set status (enable|disable)', sccp_sub)
                port_m   = re.search(r'set port (\d+)', sccp_sub)
                sccp_config = {
                    "status": status_m.group(1).capitalize() if status_m else "-",
                    "port":   port_m.group(1) if port_m else "2000",
                }
            rows.append({
                "name":    name,
                "comment": comment_m.group(1) if comment_m else "-",
                "sip":     sip_config,
                "sccp":    sccp_config,
            })
        return rows

    def parse_waf(self) -> list:
        block = self._extract_block("waf profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            signatures = []
            disabled_m = None
            sig_sub = _depth_extract(body, "signature")
            if sig_sub:
                disabled_m = re.search(r'set disabled-signature (.*)', sig_sub)
                pos = 0
                while True:
                    mc_match = re.search(r'config main-class (\d+)', sig_sub[pos:])
                    if not mc_match:
                        break
                    class_id  = mc_match.group(1)
                    abs_start = pos + mc_match.start()
                    depth = 0
                    lines = sig_sub[abs_start:].splitlines()
                    collected = []
                    for line in lines:
                        stripped = line.strip()
                        collected.append(line)
                        if stripped.startswith("config "):
                            depth += 1
                        elif stripped == "end":
                            depth -= 1
                            if depth == 0:
                                break
                    mc_block = "\n".join(collected)
                    action_m   = re.search(r'set action (\S+)', mc_block)
                    status_m   = re.search(r'set status (enable|disable)', mc_block)
                    severity_m = re.search(r'set severity (\S+)', mc_block)
                    signatures.append({
                        "Class ID":   class_id,
                        "Class Name": WAF_CLASS_NAMES.get(class_id, f"Class {class_id}"),
                        "Status":     status_m.group(1).capitalize() if status_m else "Disable",
                        "Action":     action_m.group(1).capitalize() if action_m else "Alert",
                        "Severity":   severity_m.group(1).capitalize() if severity_m else "-",
                    })
                    pos = abs_start + len(mc_block)
            constraints = []
            constraint_sub = _depth_extract(body, "constraint")
            if constraint_sub:
                constraint_types = [
                    "header-length", "content-length", "param-length",
                    "line-length", "url-param-length", "version",
                    "method", "hostname", "malformed", "max-cookie",
                    "max-header-line", "max-url-param", "max-range-segment"
                ]
                for ct in constraint_types:
                    ct_sub = _depth_extract(constraint_sub, ct)
                    if ct_sub:
                        status_m   = re.search(r'set status (enable|disable)', ct_sub)
                        action_m   = re.search(r'set action (\S+)', ct_sub)
                        log_m      = re.search(r'set log (enable|disable)', ct_sub)
                        severity_m = re.search(r'set severity (\S+)', ct_sub)
                        length_m   = re.search(r'set length (\d+)', ct_sub)
                        constraints.append({
                            "Constraint": ct.replace("-", " ").title(),
                            "Status":     status_m.group(1).capitalize() if status_m else "Disable",
                            "Action":     action_m.group(1).capitalize() if action_m else "-",
                            "Log":        log_m.group(1).capitalize() if log_m else "-",
                            "Severity":   severity_m.group(1).capitalize() if severity_m else "-",
                            "Length":     length_m.group(1) if length_m else "-",
                        })
            rows.append({
                "name":         name,
                "comment":      comment_m.group(1) if comment_m else "-",
                "signatures":   signatures,
                "disabled_sigs": disabled_m.group(1).strip() if disabled_m else "-",
                "constraints":  constraints,
            })
        return rows

    def parse_ssl_inspection(self) -> list:
        block = self._extract_block("firewall ssl-ssh-profile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            comment_m   = re.search(r'set comment "([^"]+)"', body)
            caname_m    = re.search(r'set caname "([^"]+)"', body)
            untrusted_m = re.search(r'set untrusted-caname "([^"]+)"', body)
            protocols   = []
            for proto in ["https", "ftps", "imaps", "pop3s", "smtps", "ssh"]:
                sub = self._extract_sub_block(body, proto)
                if sub:
                    ports_m  = re.search(r'set ports ([\d\s]+)', sub)
                    status_m = re.search(r'set status (\S+)', sub)
                    unsup_m  = re.search(r'set unsupported-ssl-version (\S+)', sub)
                    protocols.append({
                        "Protocol":       proto.upper(),
                        "Ports":          ports_m.group(1).strip() if ports_m else "-",
                        "Status":         status_m.group(1).replace("-", " ").title() if status_m else "-",
                        "Unsupported SSL": unsup_m.group(1).capitalize() if unsup_m else "-",
                    })
            rows.append({
                "name":           name,
                "comment":        comment_m.group(1) if comment_m else "-",
                "ca_cert":        caname_m.group(1) if caname_m else "-",
                "untrusted_cert": untrusted_m.group(1) if untrusted_m else "-",
                "protocols":      protocols,
            })
        return rows

    def parse_web_rating_override(self) -> list:
        block = self._extract_block("webfilter ftgd-local-rating")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for url, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            status_m  = re.search(r'set status (\S+)', body)
            cat_m     = re.search(r'set rating (\d+)', body)
            cat_id    = cat_m.group(1) if cat_m else "-"
            rows.append({
                "URL":           url,
                "Rating ID":     cat_id,
                "Category Name": FTGD_CATEGORIES.get(cat_id, f"Category {cat_id}") if cat_id != "-" else "-",
                "Status":        status_m.group(1).capitalize() if status_m else "Enable",
                "Comment":       comment_m.group(1) if comment_m else "-",
            })
        return rows

    def parse_web_profile_override(self) -> list:
        block = self._extract_block("webfilter override")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit (\d+)(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for oid, body in entries:
            initiator_m  = re.search(r'set initiator "([^"]+)"', body)
            scope_m      = re.search(r'set scope (\S+)', body)
            oldprofile_m = re.search(r'set old-profile "([^"]+)"', body)
            newprofile_m = re.search(r'set profile "([^"]+)"', body)
            status_m     = re.search(r'set status (\S+)', body)
            expires_m    = re.search(r'set expires (.*)', body)
            rows.append({
                "Initiator":        initiator_m.group(1) if initiator_m else "-",
                "Scope":            scope_m.group(1).capitalize() if scope_m else "-",
                "Original Profile": oldprofile_m.group(1) if oldprofile_m else "-",
                "New Profile":      newprofile_m.group(1) if newprofile_m else "-",
                "Status":           status_m.group(1).capitalize() if status_m else "-",
                "Expires":          expires_m.group(1).strip() if expires_m else "-",
            })
        return rows
