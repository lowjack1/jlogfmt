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
    """Table layout configuration for 3-column display."""

    level_width: int
    timestamp_width: int
    message_width: int
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

    def __init__(self, terminal_width: int = None):
        self.terminal_width = terminal_width or self._get_terminal_width()

    def _get_terminal_width(self) -> int:
        """Get terminal width with fallback."""
        try:
            return os.get_terminal_size().columns
        except (OSError, ValueError):
            return 120  # Fallback width

    def calculate_layout(self) -> TableLayout:
        """Calculate optimal column widths for 3-column layout."""
        border_overhead = 9
        available_width = (
            self.terminal_width
            - self.LEVEL_WIDTH
            - self.TIMESTAMP_WIDTH
            - border_overhead
        )
        
        # Now that we don't have a right border, use all available width for message
        # Still set a reasonable minimum
        message_width = max(30, available_width)

        return TableLayout(
            level_width=self.LEVEL_WIDTH,
            timestamp_width=self.TIMESTAMP_WIDTH,
            message_width=message_width,
            terminal_width=self.terminal_width,
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
                # Pad the line to exactly the specified width
                lines.append(current_line.ljust(width))
                current_line = continuation_prefix + word
            else:
                current_line = test_line

        if current_line.strip():
            # Pad the final line to exactly the specified width
            lines.append(current_line.ljust(width))

        return lines if lines else ["".ljust(width)]

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

    def render_footer(self) -> None:
        """Render table footer."""
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

    def render_separator(self) -> None:
        """Render row separator."""
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

    def render_entry(self, entry: LogEntry, is_first: bool = True) -> None:
        """Render a single log entry in 3-column format with fields on separate lines."""
        level_color = LogLevelMapper.get_color(entry.level)
        timestamp = self.formatter.format_timestamp(entry.timestamp)

        # Handle message and fields separately
        message = entry.message or ""
        
        # Wrap the main message
        message_lines = self.formatter.wrap_text(
            message, self.layout.message_width
        ) if message else [""]

        # Render the main message lines first
        for i, msg_part in enumerate(message_lines):
            # Ensure proper column width padding - text must fit exactly in the column
            msg_part = msg_part.ljust(self.layout.message_width)

            if i == 0:
                # First line with level and timestamp
                level_padded = entry.level.ljust(self.layout.level_width)
                timestamp_padded = timestamp.ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{level_color}{Colors.BOLD} {level_padded} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {timestamp_padded} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.NC}"
                )
            else:
                # Continuation lines for message
                empty_level = "".ljust(self.layout.level_width)
                empty_timestamp = "".ljust(self.layout.timestamp_width)
                print(
                    f"{Colors.DIM_GRAY}│{Colors.NC}{Colors.WHITE} {empty_level} {Colors.NC}{Colors.DIM_GRAY}│{Colors.NC} {empty_timestamp} {Colors.DIM_GRAY}│{Colors.NC} {msg_part} {Colors.NC}"
                )

        # Add each field on its own line if they exist
        if entry.fields:
            # Handle legacy raw fields first
            if "raw_fields" in entry.fields and len(entry.fields) == 1:
                raw_content = str(entry.fields["raw_fields"]).strip()
                if raw_content:
                    # Indent field content by 2 spaces from message column
                    field_lines = self.formatter.wrap_text(raw_content, self.layout.message_width - 6)  # Account for "  ├─ "
                    
                    for k, field_line in enumerate(field_lines):
                        if k == 0:
                            field_formatted = f"  {Colors.DIM_GRAY}├─ {Colors.CYAN}{field_line}{Colors.NC}"
                        else:
                            # Continuation lines with proper indentation
                            field_formatted = f"     {Colors.CYAN}{field_line}{Colors.NC}"
                        
                        # Pad to exact message column width
                        field_formatted = field_formatted.ljust(self.layout.message_width)
                        
                        # Print with proper table borders
                        empty_level = "".ljust(self.layout.level_width)
                        empty_timestamp = "".ljust(self.layout.timestamp_width)
                        print(
                            f"{Colors.DIM_GRAY}│{Colors.NC} {empty_level} {Colors.DIM_GRAY}│{Colors.NC} {empty_timestamp} {Colors.DIM_GRAY}│{Colors.NC} {field_formatted} {Colors.NC}"
                        )
            else:
                # Handle regular key-value fields
                for key, value in entry.fields.items():
                    if key != "raw_fields" and value is not None:
                        value_str = str(value).strip()
                        if value_str:
                            # Format key and value with colors, handle wrapping separately
                            colored_key = f"{Colors.CYAN}{key}={Colors.NC}"
                            
                            # Calculate available width for the value (indent by 2 spaces from message column)
                            available_width = self.layout.message_width - len(f"  ├─ {key}=")
                            value_wrapped = self.formatter.wrap_text(value_str, available_width)
                            
                            for k, value_line in enumerate(value_wrapped):
                                if k == 0:
                                    # First line with tree connector and colored key (indented by 2 spaces)
                                    field_formatted = f"  {Colors.DIM_GRAY}├─ {colored_key}{Colors.CYAN}{value_line}{Colors.NC}"
                                else:
                                    # Continuation lines with proper indentation (no vertical bar)
                                    indent_spaces = " " * (len(f"  ├─ {key}="))
                                    field_formatted = f"{indent_spaces}{Colors.CYAN}{value_line}{Colors.NC}"
                                
                                # Pad to exact message column width
                                field_formatted = field_formatted.ljust(self.layout.message_width)
                                
                                # Print with proper table borders
                                empty_level = "".ljust(self.layout.level_width)
                                empty_timestamp = "".ljust(self.layout.timestamp_width)
                                print(
                                    f"{Colors.DIM_GRAY}│{Colors.NC} {empty_level} {Colors.DIM_GRAY}│{Colors.NC} {empty_timestamp} {Colors.DIM_GRAY}│{Colors.NC} {field_formatted} {Colors.NC}"
                                )


class LogFormatter:
    """Main log formatter orchestrating all components."""

    def __init__(self, terminal_width: int = None):
        self.parser = LogParser()
        self.layout_calculator = TableLayoutCalculator(terminal_width)
        self.logger = logging.getLogger(__name__)
        self.current_layout = None
        self.last_terminal_width = None

    def _get_current_layout(self) -> TableLayout:
        """Get current layout, recalculating if terminal size changed."""
        try:
            current_width = os.get_terminal_size().columns
        except (OSError, ValueError):
            current_width = 120  # Fallback
        
        # Recalculate layout if terminal width changed or not yet calculated
        if (self.current_layout is None or 
            self.last_terminal_width != current_width):
            self.layout_calculator.terminal_width = current_width
            self.current_layout = self.layout_calculator.calculate_layout()
            self.last_terminal_width = current_width
            
        return self.current_layout

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
        check_counter = 0

        for line in input_stream:
            try:
                entry = self.parser.parse_line(line)
                if not entry:
                    continue

                # Check for terminal size changes every 10 entries to avoid excessive checks
                check_counter += 1
                current_layout = self._get_current_layout()
                
                # Reinitialize if layout changed or first time
                if (not header_printed or 
                    layout is None or
                    (check_counter % 10 == 0 and 
                     layout.terminal_width != current_layout.terminal_width)):
                    
                    if header_printed and layout.terminal_width != current_layout.terminal_width:
                        # Terminal was resized, print a separator
                        print("\n" + "─" * current_layout.terminal_width)
                        print(f"Terminal resized to {current_layout.terminal_width} columns")
                        print("─" * current_layout.terminal_width + "\n")
                    
                    layout = current_layout
                    renderer = TableRenderer(layout)
                    renderer.render_header()
                    header_printed = True
                    entry_count = 0  # Reset entry count for new table

                # Add separator between entries (except for first in current table)
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
        # has_fields_column = self.analyzer.should_show_fields_column(entries) # Removed analyzer
        layout = self._get_current_layout() # Always 3-column for batch

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
