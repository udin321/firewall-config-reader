from abc import ABC, abstractmethod

class BaseFirewallParser(ABC):
    """Abstract base class all firewall parsers must implement."""

    def __init__(self, content: str):
        self.content = content

    @abstractmethod
    def get_hostname(self) -> str:
        pass

    @abstractmethod
    def parse_interfaces(self) -> list[dict]:
        pass

    @abstractmethod
    def parse_policies(self) -> list[dict]:
        """Return firewall policy rows. Return [] if not yet implemented."""
        pass