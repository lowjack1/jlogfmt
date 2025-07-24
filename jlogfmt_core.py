#!/usr/bin/env python3
"""
jlogfmt - JSON Log Formatter

A powerful command-line utility for parsing and formatting system logs with beautiful table output.

Features:
- JSON structured logs with intelligent parsing
- Legacy pipe-separated log support  
- Plain text log handling
- Systemd journal format parsing
- Smart column layout detection
- Terminal-aware responsive design
- Color-coded log levels
- Text wrapping and field formatting

Author: lowjack
License: MIT
Version: 1.0.0
"""

import json
import sys
import re
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    """Log level enumeration with color mapping."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    GIN = "GIN"
    RAW = "RAW"


@dataclass
class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[1;37m"
    GRAY = "\033[0;37m"
    DIM_GRAY = "\033[2;37m"
    NC = "\033[0m"  # No Color
    BOLD = "\033[1m"


@dataclass
class LogEntry:
    """Structured representation of a log entry."""

    level: str
    timestamp: str
    message: str
    fields: Dict[str, Any]
    is_json: bool
    raw_content: str = ""

    def __post_init__(self):
        """Normalize level to uppercase."""
        self.level = self.level.upper()


@dataclass
class TableLayout:
    """Table layout configuration."""

    level_width: int
    timestamp_width: int
    message_width: int
    fields_width: int
    has_fields_column: bool
    terminal_width: int


class LogLevelMapper:
    """Maps log levels to their corresponding colors."""

    COLOR_MAP = {
        LogLevel.ERROR: Colors.RED,
        LogLevel.WARNING: Colors.YELLOW,
        LogLevel.INFO: Colors.GREEN,
        LogLevel.DEBUG: Colors.CYAN,
        LogLevel.FATAL: Colors.PURPLE,
        LogLevel.GIN: Colors.BLUE,
        LogLevel.RAW: Colors.WHITE,
    }

    @classmethod
    def get_color(cls, level: str) -> str:
        """Get color for a log level."""
        try:
            log_level = LogLevel(level.upper())
            return cls.COLOR_MAP.get(log_level, Colors.WHITE)
        except ValueError:
            return Colors.WHITE


class LogParser:
    """Parses various log formats into structured LogEntry objects."""

    # Regex patterns for different log formats
    SYSTEMD_PATTERN = re.compile(
        r"^([A-Z][a-z]+ [0-9]+ [0-9:]+) ([^ ]+) ([^\[]+)\[([0-9]+)\]: (.*)$"
    )
    LEGACY_PATTERN = re.compile(
        r"^(DEBUG|INFO|WARNING|ERROR|FATAL)\s*\|\s*([^|]+)\s*\|\s*([^|]*)\s*(?:\|\s*(.*))?$"
    )

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into a LogEntry."""
        line = line.strip()
        if not line:
            return None

        try:
            # Try systemd format first
            systemd_result = self._parse_systemd_line(line)
            if systemd_result:
                return systemd_result

            # Try direct JSON
            json_result = self._parse_json_line(line)
            if json_result:
                return json_result

            # Fallback to plain text
            return self._parse_plain_text(line)

        except Exception as e:
            self.logger.warning(f"Error parsing line: {e}")
            return self._parse_plain_text(line)

    def _parse_systemd_line(self, line: str) -> Optional[LogEntry]:
        """Parse systemd journal format."""
        match = self.SYSTEMD_PATTERN.match(line)
        if not match:
            return None

        systemd_date = match.group(1)
        content = match.group(5)

        # Try to parse content as JSON
        try:
            json_data = json.loads(content)
            return LogEntry(
                level=json_data.get("level", "INFO"),
                timestamp=json_data.get(
                    "@timestamp", json_data.get("time", systemd_date)
                ),
                message=json_data.get("message", json_data.get("msg", "")),
                fields={
                    k: v
                    for k, v in json_data.items()
                    if k not in ["level", "message", "msg", "@timestamp", "time"]
                },
                is_json=True,
                raw_content=content,
            )
        except json.JSONDecodeError:
            # Try legacy format
            legacy_match = self.LEGACY_PATTERN.match(content)
            if legacy_match:
                return LogEntry(
                    level=legacy_match.group(1),
                    timestamp=legacy_match.group(2),
                    message=legacy_match.group(3),
                    fields={"raw_fields": legacy_match.group(4) or ""},
                    is_json=False,
                    raw_content=content,
                )

            # Plain text with level detection
            level = self._detect_level_from_content(content)
            return LogEntry(
                level=level,
                timestamp=systemd_date,
                message=content,
                fields={},
                is_json=False,
                raw_content=content,
            )

    def _parse_json_line(self, line: str) -> Optional[LogEntry]:
        """Parse direct JSON log line."""
        try:
            data = json.loads(line)
            return LogEntry(
                level=data.get("level", "INFO"),
                timestamp=data.get("@timestamp", data.get("time", "")),
                message=data.get("message", data.get("msg", "")),
                fields={
                    k: v
                    for k, v in data.items()
                    if k not in ["level", "message", "msg", "@timestamp", "time"]
                },
                is_json=True,
                raw_content=line,
            )
        except json.JSONDecodeError:
            return None

    def _parse_plain_text(self, line: str) -> LogEntry:
        """Parse plain text as a raw log entry."""
        level = self._detect_level_from_content(line)
        return LogEntry(
            level=level,
            timestamp="",
            message=line,
            fields={},
            is_json=False,
            raw_content=line,
        )

    def _detect_level_from_content(self, content: str) -> str:
        """Detect log level from content using patterns."""
        content_lower = content.lower()

        if re.search(r"error|err|exception|fail", content_lower):
            return "ERROR"
        elif re.search(r"warning|warn", content_lower):
            return "WARNING"
        elif re.search(r"debug", content_lower):
            return "DEBUG"
        elif content.startswith("[GIN]"):
            return "GIN"
        else:
            return "INFO"


class TableLayoutCalculator:
    """Calculates optimal table layout based on terminal size and content."""

    # Fixed column widths
    LEVEL_WIDTH = 8
    TIMESTAMP_WIDTH = 19
    MIN_MESSAGE_WIDTH = 25
    MIN_FIELDS_WIDTH = 20

    def __init__(self, terminal_width: int = None):
        self.terminal_width = terminal_width or self._get_terminal_width()

    def _get_terminal_width(self) -> int:
        """Get terminal width with fallback."""
        try:
            return os.get_terminal_size().columns
        except (OSError, ValueError):
            return 120  # Fallback width

    def calculate_layout(self, has_fields_column: bool) -> TableLayout:
        """Calculate optimal column widths."""
        if has_fields_column:
            return self._calculate_four_column_layout()
        else:
            return self._calculate_three_column_layout()

    def _calculate_four_column_layout(self) -> TableLayout:
        """Calculate layout for LEVEL | TIMESTAMP | MESSAGE | FIELDS."""
        # Border overhead: 4 separators + 8 spaces
        border_overhead = 12
        available_width = (
            self.terminal_width
            - self.LEVEL_WIDTH
            - self.TIMESTAMP_WIDTH
            - border_overhead
        )

        # Split remaining space: 45% message, 55% fields
        message_width = max(self.MIN_MESSAGE_WIDTH, int(available_width * 0.45))
        fields_width = available_width - message_width

        # Ensure minimum widths
        if fields_width < self.MIN_FIELDS_WIDTH:
            fields_width = self.MIN_FIELDS_WIDTH
            message_width = available_width - fields_width

        if message_width < self.MIN_MESSAGE_WIDTH:
            message_width = self.MIN_MESSAGE_WIDTH
            fields_width = available_width - message_width

        # Final adjustment to prevent overflow
        actual_total = (
            self.LEVEL_WIDTH
            + self.TIMESTAMP_WIDTH
            + message_width
            + fields_width
            + border_overhead
        )
        if actual_total > self.terminal_width:
            excess = actual_total - self.terminal_width
            if fields_width > message_width:
                fields_width = max(self.MIN_FIELDS_WIDTH, fields_width - excess)
            else:
                message_width = max(self.MIN_MESSAGE_WIDTH, message_width - excess)

        return TableLayout(
            level_width=self.LEVEL_WIDTH,
            timestamp_width=self.TIMESTAMP_WIDTH,
            message_width=message_width,
            fields_width=fields_width,
            has_fields_column=True,
            terminal_width=self.terminal_width,
        )

    def _calculate_three_column_layout(self) -> TableLayout:
        """Calculate layout for LEVEL | TIMESTAMP | MESSAGE."""
        # Border overhead: 3 separators + 6 spaces
        border_overhead = 9
        available_width = (
            self.terminal_width
            - self.LEVEL_WIDTH
            - self.TIMESTAMP_WIDTH
            - border_overhead
        )
        message_width = max(30, available_width)

        # Prevent overflow
        actual_total = (
            self.LEVEL_WIDTH + self.TIMESTAMP_WIDTH + message_width + border_overhead
        )
        if actual_total > self.terminal_width:
            excess = actual_total - self.terminal_width
            message_width = max(30, message_width - excess)

        return TableLayout(
            level_width=self.LEVEL_WIDTH,
            timestamp_width=self.TIMESTAMP_WIDTH,
            message_width=message_width,
            fields_width=0,
            has_fields_column=False,
            terminal_width=self.terminal_width,
        )


class ContentAnalyzer:
    """Analyzes log content to determine optimal display layout."""

    def __init__(self):
        self.substantial_fields_threshold = 0.25
        self.min_substantial_logs = 2

    def should_show_fields_column(self, entries: List[LogEntry]) -> bool:
        """Determine if a separate fields column should be shown."""
        if not entries:
            return False

        substantial_count = sum(
            1 for entry in entries if self._has_substantial_fields(entry)
        )
        substantial_ratio = substantial_count / len(entries)

        return (
            substantial_count >= self.min_substantial_logs
            and substantial_ratio >= self.substantial_fields_threshold
        )

    def _has_substantial_fields(self, entry: LogEntry) -> bool:
        """Check if log entry has substantial field data."""
        if not entry.fields:
            return False

        # Filter out empty or standard fields
        meaningful_fields = {
            k: v
            for k, v in entry.fields.items()
            if v and k not in ["raw_fields"] and str(v).strip()
        }

        if not meaningful_fields:
            return False

        # Check for legacy format with substantial raw fields
        if "raw_fields" in entry.fields:
            raw_fields = str(entry.fields["raw_fields"]).strip()
            return len(raw_fields) > 10

        # Check for multiple fields or complex values
        return len(meaningful_fields) >= 2 or any(
            len(str(v)) > 20 for v in meaningful_fields.values()
        )


class TextFormatter:
    """Handles text wrapping and formatting utilities."""

    @staticmethod
    def wrap_text(text: str, width: int, continuation_prefix: str = "") -> List[str]:
        """Wrap text to specified width with optional continuation prefix."""
        if not text:
            return [""]

        lines = []
        words = text.split()
        current_line = continuation_prefix

        for word in words:
            test_line = current_line + (" " if current_line.strip() else "") + word
            if len(test_line) > width and current_line.strip():
                lines.append(current_line.ljust(width))
                current_line = continuation_prefix + word
            else:
                current_line = test_line

        if current_line.strip():
            lines.append(current_line.ljust(width))

        return lines if lines else ["".ljust(width)]

    @staticmethod
    def format_fields(fields: Dict[str, Any]) -> str:
        """Format fields dictionary into a display string."""
        if not fields:
            return ""

        # Handle legacy raw fields
        if "raw_fields" in fields and len(fields) == 1:
            return str(fields["raw_fields"])

        # Format as key=value pairs
        parts = []
        for key, value in fields.items():
            if key != "raw_fields" and value is not None:
                parts.append(f"{key}={value}")

        return " ".join(parts)

    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """Format timestamp for display."""
        if not timestamp:
            return ""

        try:
            # Parse ISO format
            if "T" in timestamp and (
                "Z" in timestamp or "+" in timestamp or "-" in timestamp
            ):
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            elif len(timestamp) <= 19:
                # Already in simple format
                return timestamp
        except (ValueError, TypeError):
            pass

        return timestamp


class TableRenderer:
    """Renders formatted log tables to terminal output."""

    def __init__(self, layout: TableLayout):
        self.layout = layout
        self.formatter = TextFormatter()

    def render_header(self) -> None:
        """Render table header."""
        if self.layout.has_fields_column:
            self._render_four_column_header()
        else:
            self._render_three_column_header()

    def render_footer(self) -> None:
        """Render table footer."""
        if self.layout.has_fields_column:
            self._render_four_column_footer()
        else:
            self._render_three_column_footer()

    def render_separator(self) -> None:
        """Render row separator."""
        if self.layout.has_fields_column:
            self._render_four_column_separator()
        else:
            self._render_three_column_separator()

    def render_entry(self, entry: LogEntry, is_first: bool = True) -> None:
        """Render a single log entry."""
        if self.layout.has_fields_column:
            self._render_four_column_entry(entry)
        else:
            self._render_three_column_entry(entry)

    def _render_four_column_header(self) -> None:
        """Render 4-column header: LEVEL | TIMESTAMP | MESSAGE | FIELDS."""
        l, t, m, f = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
            self.layout.fields_width,
        )

        border = (
            f"{Colors.DIM_GRAY}┌"
            + "─" * (l + 2)
            + "┬"
            + "─" * (t + 2)
            + "┬"
            + "─" * (m + 2)
            + "┬"
            + "─" * (f + 2)
            + f"{Colors.NC}"
        )
        header = f'{Colors.DIM_GRAY}│{Colors.NC} {"LEVEL".ljust(l)} {Colors.DIM_GRAY}│{Colors.NC} {"TIMESTAMP".ljust(t)} {Colors.DIM_GRAY}│{Colors.NC} {"MESSAGE".ljust(m)} {Colors.DIM_GRAY}│{Colors.NC} {"FIELDS".ljust(f)} {Colors.NC}'
        separator = (
            f"{Colors.DIM_GRAY}├"
            + "─" * (l + 2)
            + "┼"
            + "─" * (t + 2)
            + "┼"
            + "─" * (m + 2)
            + "┼"
            + "─" * (f + 2)
            + f"{Colors.NC}"
        )

        print(border)
        print(header)
        print(separator)

    def _render_three_column_header(self) -> None:
        """Render 3-column header: LEVEL | TIMESTAMP | MESSAGE."""
        l, t, m = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
        )

        border = (
            f"{Colors.DIM_GRAY}┌"
            + "─" * (l + 2)
            + "┬"
            + "─" * (t + 2)
            + "┬"
            + "─" * (m + 2)
            + f"{Colors.NC}"
        )
        header = f'{Colors.DIM_GRAY}│{Colors.NC} {"LEVEL".ljust(l)} {Colors.DIM_GRAY}│{Colors.NC} {"TIMESTAMP".ljust(t)} {Colors.DIM_GRAY}│{Colors.NC} {"MESSAGE".ljust(m)} {Colors.NC}'
        separator = (
            f"{Colors.DIM_GRAY}├"
            + "─" * (l + 2)
            + "┼"
            + "─" * (t + 2)
            + "┼"
            + "─" * (m + 2)
            + f"{Colors.NC}"
        )

        print(border)
        print(header)
        print(separator)

    def _render_four_column_footer(self) -> None:
        """Render 4-column footer."""
        l, t, m, f = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
            self.layout.fields_width,
        )
        footer = (
            f"{Colors.DIM_GRAY}└"
            + "─" * (l + 2)
            + "┴"
            + "─" * (t + 2)
            + "┴"
            + "─" * (m + 2)
            + "┴"
            + "─" * (f + 2)
            + f"{Colors.NC}"
        )
        print(footer)

    def _render_three_column_footer(self) -> None:
        """Render 3-column footer."""
        l, t, m = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
        )
        footer = (
            f"{Colors.DIM_GRAY}└"
            + "─" * (l + 2)
            + "┴"
            + "─" * (t + 2)
            + "┴"
            + "─" * (m + 2)
            + f"{Colors.NC}"
        )
        print(footer)

    def _render_four_column_separator(self) -> None:
        """Render 4-column row separator."""
        l, t, m, f = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
            self.layout.fields_width,
        )
        separator = (
            f"{Colors.DIM_GRAY}├"
            + "─" * (l + 2)
            + "┼"
            + "─" * (t + 2)
            + "┼"
            + "─" * (m + 2)
            + "┼"
            + "─" * (f + 2)
            + f"{Colors.NC}"
        )
        print(separator)

    def _render_three_column_separator(self) -> None:
        """Render 3-column row separator."""
        l, t, m = (
            self.layout.level_width,
            self.layout.timestamp_width,
            self.layout.message_width,
        )
        separator = (
            f"{Colors.DIM_GRAY}├"
            + "─" * (l + 2)
            + "┼"
            + "─" * (t + 2)
            + "┼"
            + "─" * (m + 2)
            + f"{Colors.NC}"
        )
        print(separator)

    def _render_four_column_entry(self, entry: LogEntry) -> None:
        """Render entry in 4-column format."""
        level_color = LogLevelMapper.get_color(entry.level)
        timestamp = self.formatter.format_timestamp(entry.timestamp)

        message_lines = self.formatter.wrap_text(
            entry.message, self.layout.message_width
        )
        fields_text = self.formatter.format_fields(entry.fields)
        fields_lines = (
            self.formatter.wrap_text(fields_text, self.layout.fields_width)
            if fields_text
            else ["".ljust(self.layout.fields_width)]
        )

        max_lines = max(len(message_lines), len(fields_lines))

        for i in range(max_lines):
            msg_part = (
                message_lines[i]
                if i < len(message_lines)
                else "".ljust(self.layout.message_width)
            )
            field_part = (
                fields_lines[i]
                if i < len(fields_lines)
                else "".ljust(self.layout.fields_width)
            )

            if i == 0:
                # First line with level and timestamp
                level_padded = entry.level.ljust(self.layout.level_width)
                timestamp_padded = timestamp.ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{level_color}{Colors.BOLD} {level_padded} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {timestamp_padded} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.DIM_GRAY}│{Colors.NC} {field_part} {Colors.NC}"
                )
            else:
                # Continuation lines
                empty_level = "".ljust(self.layout.level_width)
                empty_timestamp = "".ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{Colors.WHITE} {empty_level} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {empty_timestamp} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.DIM_GRAY}│{Colors.NC} {field_part} {Colors.NC}"
                )

    def _render_three_column_entry(self, entry: LogEntry) -> None:
        """Render entry in 3-column format with merged message and fields."""
        level_color = LogLevelMapper.get_color(entry.level)
        timestamp = self.formatter.format_timestamp(entry.timestamp)

        # Merge message and fields for 3-column layout
        message_parts = []
        if entry.message:
            message_parts.append(entry.message)

        fields_text = self.formatter.format_fields(entry.fields)
        if fields_text:
            message_parts.append(fields_text)

        merged_message = " | ".join(message_parts) if message_parts else ""
        message_lines = self.formatter.wrap_text(
            merged_message, self.layout.message_width
        )

        for i, msg_part in enumerate(message_lines):
            msg_part = msg_part.ljust(self.layout.message_width)

            if i == 0:
                # First line with level and timestamp
                level_padded = entry.level.ljust(self.layout.level_width)
                timestamp_padded = timestamp.ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{level_color}{Colors.BOLD} {level_padded} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {timestamp_padded} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.NC}"
                )
            else:
                # Continuation lines
                empty_level = "".ljust(self.layout.level_width)
                empty_timestamp = "".ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{Colors.WHITE} {empty_level} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {empty_timestamp} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.NC}"
                )


class LogFormatter:
    """Main log formatter orchestrating all components."""

    def __init__(self, terminal_width: int = None):
        self.parser = LogParser()
        self.analyzer = ContentAnalyzer()
        self.layout_calculator = TableLayoutCalculator(terminal_width)
        self.logger = logging.getLogger(__name__)

    def format_logs(self, input_stream=None) -> None:
        """Format logs from input stream and render to stdout."""
        input_stream = input_stream or sys.stdin

        try:
            # Check if this is a streaming mode (like from journalctl -f)
            # by trying to read with a small timeout
            is_streaming = self._is_streaming_input(input_stream)
            
            if is_streaming:
                self._format_streaming_logs(input_stream)
            else:
                self._format_batch_logs(input_stream)

        except KeyboardInterrupt:
            self.logger.info("Formatting interrupted by user")
        except Exception as e:
            self.logger.error(f"Error formatting logs: {e}")
            raise

    def _is_streaming_input(self, input_stream) -> bool:
        """Detect if input is streaming (like from journalctl -f)."""
        # Check if we're running with the -f flag (passed through environment or args)
        import os
        
        # Check if parent process contains journalctl with -f
        try:
            import psutil
            parent = psutil.Process().parent()
            if parent and 'journalctl' in parent.name() and '-f' in ' '.join(parent.cmdline()):
                return True
        except:
            pass
        
        # Check environment variable that can be set by the calling script
        if os.environ.get('JLOGFMT_STREAMING', '').lower() == 'true':
            return True
            
        # Fallback: if stdin is not a tty and we have piped input, assume streaming for safety
        return not input_stream.isatty()

    def _format_streaming_logs(self, input_stream) -> None:
        """Format logs in streaming mode - process line by line."""
        header_printed = False
        layout = None
        renderer = None
        entry_count = 0

        for line in input_stream:
            try:
                entry = self.parser.parse_line(line)
                if not entry:
                    continue

                # Initialize layout and renderer on first valid entry
                if not header_printed:
                    # For streaming, assume 3-column layout initially
                    layout = self.layout_calculator.calculate_layout(False)
                    renderer = TableRenderer(layout)
                    renderer.render_header()
                    header_printed = True

                # Add separator between entries (except for first)
                if entry_count > 0:
                    renderer.render_separator()
                
                renderer.render_entry(entry, entry_count == 0)
                entry_count += 1
                
                # Flush output for real-time display
                sys.stdout.flush()

            except Exception as e:
                self.logger.debug(f"Failed to parse line: {e}")
                continue

    def _format_batch_logs(self, input_stream) -> None:
        """Format logs in batch mode - original behavior."""
        # Parse all log entries
        entries = self._parse_all_entries(input_stream)
        if not entries:
            self.logger.warning("No valid log entries found")
            return

        # Determine layout
        has_fields_column = self.analyzer.should_show_fields_column(entries)
        layout = self.layout_calculator.calculate_layout(has_fields_column)

        # Render table
        renderer = TableRenderer(layout)
        self._render_table(renderer, entries)

    def _parse_all_entries(self, input_stream) -> List[LogEntry]:
        """Parse all log entries from input stream."""
        entries = []

        for line in input_stream:
            try:
                entry = self.parser.parse_line(line)
                if entry:
                    entries.append(entry)
            except Exception as e:
                self.logger.debug(f"Failed to parse line: {e}")
                continue

        return entries

    def _render_table(self, renderer: TableRenderer, entries: List[LogEntry]) -> None:
        """Render complete table with entries."""
        renderer.render_header()

        for i, entry in enumerate(entries):
            if i > 0:
                renderer.render_separator()
            renderer.render_entry(entry, i == 0)

        renderer.render_footer()


def setup_logging(level: str = "WARNING") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    """Main entry point."""
    setup_logging()

    formatter = LogFormatter()
    formatter.format_logs()


if __name__ == "__main__":
    main()
