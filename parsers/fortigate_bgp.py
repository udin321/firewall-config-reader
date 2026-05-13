"""
parsers/fortigate_bgp.py
Parse "config router bgp" block from a FortiGate .conf file.
"""
import re
from typing import Any


class FortiGateBGPParser:
    def __init__(self, raw_text: str):
        self.raw = raw_text

    # ── internal helpers ──────────────────────────────────────────────────
    @staticmethod
    def _extract_block(text: str, block_keyword: str) -> str:
        """Return the text between 'config <keyword>' and matching 'end'."""
        pattern = rf"config\s+{re.escape(block_keyword)}\s*\n(.*?)\nend(?:\s|$)"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1) if m else ""

    @staticmethod
    def _parse_entries(block: str) -> list[dict]:
        """Parse edit … next stanzas inside a config block."""
        entries: list[dict] = []
        for chunk in re.split(r"\n\s*next\b", block):
            m = re.search(r"edit\s+(\S+)", chunk)
            if not m:
                continue
            entry: dict[str, Any] = {"name": m.group(1).strip('"')}
            for key, val in re.findall(r"set\s+(\S+)\s+(.+)", chunk):
                entry[key.strip()] = val.strip().strip('"')
            entries.append(entry)
        return entries

    # ── public API ────────────────────────────────────────────────────────
    def get_bgp_summary(self) -> dict:
        bgp_block = self._extract_block(self.raw, "router bgp")
        if not bgp_block:
            return {}

        summary: dict[str, Any] = {}

        # Top-level scalars
        for key in ("as", "router-id", "keepalive-timer", "holdtime-timer",
                    "ebgp-multipath", "ibgp-multipath", "graceful-restart"):
            m = re.search(rf"set\s+{re.escape(key)}\s+(\S+)", bgp_block)
            if m:
                summary[key] = m.group(1)

        # Networks
        net_block = self._extract_block(bgp_block, "network")
        summary["networks"] = self._parse_entries(net_block)

        # Neighbours
        nb_block = self._extract_block(bgp_block, "neighbor")
        summary["neighbors"] = self._parse_entries(nb_block)

        # Neighbor groups
        ng_block = self._extract_block(bgp_block, "neighbor-group")
        summary["neighbor_groups"] = self._parse_entries(ng_block)

        # Redistribute
        rd_block = self._extract_block(bgp_block, "redistribute")
        summary["redistribute"] = self._parse_entries(rd_block)

        return summary
