from abc import ABC, abstractmethod
from backend.models.schemas import LogEvent


class BaseLogParser(ABC):
    """
    Abstract base class for all log parsers.
    Each parser must implement parse_line() and parse_file().
    """

    @abstractmethod
    def parse_line(self, line: str, line_num: int) -> LogEvent | None:
        """
        Parse a single raw log line into a structured LogEvent.
        Returns None if the line is blank or unparseable.
        """
        ...

    def parse_file(self, content: str) -> list[LogEvent]:
        """
        Parse an entire log file (as a string) line by line.
        Skips blank lines and lines that fail to parse.
        """
        events = []
        for i, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = self.parse_line(stripped, i)
            if event is not None:
                events.append(event)
        return events