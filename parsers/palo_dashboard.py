"""Palo Alto Dashboard parser."""

from parsers.paloalto import PaloAltoParser


class PaloDashboardParser(PaloAltoParser):
    """
    Parser for the Dashboard tab.
    Wraps get_system_info() and get_ha_info() from the base PaloAltoParser,
    plus adds a convenience summary method used by render_pa_dashboard().
    """

    def __init__(self, root):
        super().__init__(root)

    def get_dashboard_data(self) -> dict:
        """
        Return a combined dict with system info and HA info,
        ready for the dashboard view to consume.
        """
        data = {}

        # System info (hostname, model, serial, SW version, etc.)
        try:
            data["system"] = self.get_system_info()
        except Exception:
            data["system"] = {}

        # High-Availability info
        try:
            data["ha"] = self.get_ha_info()
        except Exception:
            data["ha"] = {}

        return data
