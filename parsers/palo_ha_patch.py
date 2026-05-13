"""
parsers/palo_ha_patch.py
Drop-in HA parser fixes for Palo Alto.
Merge this into your existing parsers/paloalto.py or parsers/palo_ha.py.

Key fixes
---------
- device-priority now parsed (default 100 if absent)
- passive-link-state now parsed (default shutdown)
- monitor-fail-hold-down-time now parsed (default 1)
- link-monitoring / path-monitoring enabled-by-default logic
"""
import xml.etree.ElementTree as ET


class PaloHAPatchMixin:
    """
    Mix this into PaloAltoParser (or call get_ha_info_patched directly).
    Assumes self.root is the ET.Element root of the config XML.
    """

    def get_ha_info_patched(self) -> dict:
        root = self.root
        ha = root.find(".//high-availability")
        if ha is None:
            return {"enabled": False}

        def _txt(node, path, default=""):
            el = node.find(path)
            return el.text.strip() if el is not None and el.text else default

        def _bool(node, path, panos_default=True):
            """HA features that are enabled by default in PAN-OS."""
            el = node.find(path)
            if el is None:
                return panos_default
            return el.text.strip().lower() in ("yes", "true", "1", "enabled")

        enabled = _bool(ha, "enabled", panos_default=False)
        if not enabled:
            return {"enabled": False}

        result: dict = {
            "enabled": True,
            "mode": _txt(ha, "mode", "active-passive"),
            "group_id": _txt(ha, "group-id", "1"),
            "description": _txt(ha, "description", ""),
        }

        # ── Election / General ────────────────────────────────────────────
        election = ha.find("election-option") or ha.find("group/election-option") or ha
        result["election"] = {
            "device_priority":     _txt(election, "device-priority", "100"),
            "preemptive":          _txt(election, "preemptive", "no"),
            "heartbeat_backup":    _txt(election, "heartbeat-backup", "no"),
            "timers_profile":      _txt(election, "timers/profile", "Recommended"),
        }

        # ── Active / Passive ──────────────────────────────────────────────
        ap = ha.find("active-passive") or ha.find("group/active-passive")
        if ap is not None:
            result["active_passive"] = {
                "passive_link_state":          _txt(ap, "passive-link-state", "shutdown"),
                "monitor_fail_hold_down_time": _txt(ap, "monitor-fail-hold-down-time", "1"),
            }
        else:
            result["active_passive"] = {
                "passive_link_state":          "shutdown",
                "monitor_fail_hold_down_time": "1",
            }

        # ── HA1 / HA2 interfaces ──────────────────────────────────────────
        for intf_name in ("ha1", "ha1-backup", "ha2", "ha2-backup"):
            intf = ha.find(intf_name) or ha.find(f"group/{intf_name}")
            if intf is not None:
                result[intf_name] = {
                    "port":       _txt(intf, "port"),
                    "ip_address": _txt(intf, "ip-address"),
                    "netmask":    _txt(intf, "netmask"),
                    "gateway":    _txt(intf, "gateway"),
                    "encryption": _txt(intf, "encryption", "no"),
                }

        # ── Link Monitoring ────────────────────────────────────────────────
        lmon = ha.find("link-monitoring") or ha.find("group/link-monitoring")
        if lmon is not None:
            result["link_monitoring"] = {
                "enabled":       _txt(lmon, "enable", "yes"),   # PAN-OS default: yes
                "failure_condition": _txt(lmon, "failure-condition", "any"),
                "groups": [
                    {
                        "name": g.find("name").text if g.find("name") is not None else "",
                        "enabled": _txt(g, "enable", "yes"),
                        "failure_condition": _txt(g, "failure-condition", "any"),
                        "interfaces": [i.text for i in g.findall("interface/member") if i.text],
                    }
                    for g in lmon.findall("group/entry")
                ],
            }
        else:
            # PAN-OS enables link-monitoring by default even if tag absent
            result["link_monitoring"] = {"enabled": "yes", "failure_condition": "any", "groups": []}

        # ── Path Monitoring ────────────────────────────────────────────────
        pmon = ha.find("path-monitoring") or ha.find("group/path-monitoring")
        if pmon is not None:
            result["path_monitoring"] = {
                "enabled":       _txt(pmon, "enable", "yes"),
                "failure_condition": _txt(pmon, "failure-condition", "any"),
                "groups": [
                    {
                        "name": g.find("name").text if g.find("name") is not None else "",
                        "enabled": _txt(g, "enable", "yes"),
                        "failure_condition": _txt(g, "failure-condition", "any"),
                        "ping_interval": _txt(g, "ping-interval", "200"),
                        "ping_count":    _txt(g, "ping-count", "10"),
                        "destinations":  [d.text for d in g.findall("destination/entry/dst") if d.text],
                    }
                    for g in pmon.findall("group/entry")
                ],
            }
        else:
            result["path_monitoring"] = {"enabled": "yes", "failure_condition": "any", "groups": []}

        return result
