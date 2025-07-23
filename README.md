# jlogfmt - JSON Log Formatter

Command-line utility for parsing and formatting system logs with beautiful table output.

## 🚀 Features

**jlogfmt** is a powerful log formatting tool that automatically detects and beautifully formats various log types:

### Core Features
- **Smart Format Detection**: Automatically handles JSON, legacy pipe-separated, and plain text logs
- **Beautiful Table Output**: Professional table formatting with borders and color coding
- **Intelligent Layout**: Dynamically adjusts column widths based on content
- **Terminal Responsive**: Adapts to terminal width for optimal display
- **Production Ready**: Modular, typed Python codebase with comprehensive error handling

### Supported Log Formats

#### JSON Logs (Production/Systemd)
```json
{
  "@timestamp": "2025-01-21T10:30:15.123Z",
  "level": "INFO",
  "message": "Processing Message",
  "messageID": "uuid-123",
  "language": "en"
}
```

#### Legacy Pipe-Separated Logs
```
INFO | 2025-01-21 10:30:15 | Processing Message | messageID=uuid-123 language=en
```

#### Plain Text Logs
```
Jan 21 10:30:15 hostname service[1234]: [GIN] 2025/01/21 - 10:30:15 | 200 | GET /health
```

## 📊 Beautiful Output

```
┌──────────┬─────────────────────┬────────────────────────────────────────┬──────────────────────────────────────┐
│ LEVEL    │ TIMESTAMP           │ MESSAGE                                │ FIELDS                               │
├──────────┼─────────────────────┼────────────────────────────────────────┼──────────────────────────────────────┤
│ INFO     │ 2025-01-21 10:30:15 │ Processing Message                     │ messageID=abc-123 language=en        │
├──────────┼─────────────────────┼────────────────────────────────────────┼──────────────────────────────────────┤
│ ERROR    │ 2025-01-21 10:30:16 │ Processing failed                      │ error="API timeout" messageID=abc-123│
└──────────┴─────────────────────┴────────────────────────────────────────┴──────────────────────────────────────┘
```

### Color Coding
- **ERROR** - Red
- **WARNING** - Yellow  
- **INFO** - Green
- **DEBUG** - Cyan
- **FATAL** - Magenta

## 🛠️ Installation

### Quick Install (Recommended)
```bash
cd /path/to/project
./install.sh
```

This creates convenient aliases:
- `jlogs` - Main log viewer command with simple interface
- `jlogfmt` - Advanced JSON log formatter with full options

### Manual Usage
```bash
# Make executable
chmod +x jlogfmt jlogs

# Use directly
./jlogfmt -s myservice -f
./jlogs myservice table
```

## 📖 Usage

### Basic Commands (jlogs wrapper)
```bash
# View recent logs in beautiful table format
jlogs myservice table

# Follow logs in real-time with colors
jlogs myservice follow

# Show only errors and warnings
jlogs myservice errors

# Show today's logs
jlogs myservice today
```

### Advanced Commands (jlogfmt direct)
```bash
# Beautiful table format (default: last hour)
jlogfmt -s myservice

# Follow logs in real-time with table format
jlogfmt -s myservice -f

# Show last 6 hours
jlogfmt -s myservice -h 6

# Show specific date
jlogfmt -s myservice -d 2025-01-20

# Show only errors and warnings
jlogfmt -s myservice -e

# Combine options
jlogfmt -s nginx -e -f    # Follow only errors in table format
```

### Command Reference

#### jlogfmt Options
```
-s, --service NAME   Service name (required)
-f, --follow         Follow logs in real-time
-h, --hours N        Show logs from last N hours (default: 1)
-d, --date DATE      Show logs from specific date (YYYY-MM-DD)
-e, --errors         Show only errors and warnings
--help               Show help message
```

#### jlogs Commands
```
jlogs <service> [command]

Commands:
  follow           Follow logs in real-time with colors
  errors           Show only errors and warnings  
  today            Show today's logs
  table            Show last hour in table format (jlogfmt)
  table-follow     Follow logs in table format (jlogfmt)
  help             Show help message
```

## 🏗️ Architecture

jlogfmt is built with a modular, production-ready architecture:

### Core Components
- **`jlogfmt`** - Main CLI script with argument parsing
- **`jlogfmt_core.py`** - Production-ready Python formatter engine
- **`jlogs`** - Simple wrapper for common operations

### Python Modules
- **`LogParser`** - Handles all log format parsing (JSON, legacy, plain text)
- **`ContentAnalyzer`** - Determines optimal table layout based on content
- **`TableLayoutCalculator`** - Calculates responsive column widths
- **`TableRenderer`** - Renders beautiful formatted output
- **`TextFormatter`** - Text wrapping and field formatting utilities

### Key Features
- **Type Safety**: Full type hints throughout
- **Error Handling**: Comprehensive exception handling and fallbacks
- **Performance**: Optimized parsing with compiled regex patterns
- **Extensibility**: Easy to add new log formats and renderers
- **Testing**: Modular design for easy unit testing

## 🔧 Technical Details

### Smart Column Layout
jlogfmt automatically determines the optimal table layout:

- **3-Column Layout**: `LEVEL | TIMESTAMP | MESSAGE` (merged fields)
- **4-Column Layout**: `LEVEL | TIMESTAMP | MESSAGE | FIELDS` (when substantial field data exists)

### Text Wrapping
- Smart word wrapping at word boundaries
- Continuation lines for multi-line content
- No truncation - all content is displayed
- Responsive to terminal width

### Format Detection
1. **Systemd Format**: Parses `Jan 21 10:30:15 hostname service[pid]: content`
2. **JSON Content**: Attempts JSON parsing of log content
3. **Legacy Format**: Recognizes `LEVEL | TIMESTAMP | MESSAGE | FIELDS`
4. **Plain Text**: Falls back with intelligent level detection

## 🚀 Examples

### Development Workflow
```bash
# Quick error check
jlogs myservice errors

# Monitor in real-time
jlogs myservice table-follow

# Investigate specific timeframe  
jlogfmt -s myservice -d 2025-01-20 -e
```

### Production Monitoring
```bash
# Monitor multiple services
jlogfmt -s nginx -f &
jlogfmt -s backend -f &  
jlogfmt -s database -f &

# Error analysis
jlogfmt -s nginx -e -h 24    # Last 24 hours of errors
```

### Log Analysis
```bash
# Pipe to other tools
jlogfmt -s myservice -h 6 | grep "messageID=abc-123"

# Save formatted output
jlogfmt -s myservice -d 2025-01-20 > formatted_logs.txt
```

## 🐛 Troubleshooting

### Common Issues
1. **Python not found**: Install `python3`
2. **Permission denied**: Run `chmod +x jlogfmt jlogs`
3. **No logs shown**: Check service name exists: `systemctl status myservice`
4. **JSON parsing errors**: jlogfmt handles this automatically with fallbacks

### Debug Mode
```bash
# Check raw log output
journalctl -u myservice --since "1 hour ago" | head -10

# Test Python formatter directly
echo '{"level": "INFO", "message": "test"}' | python3 jlogfmt_core.py
```

## 🔄 Migration from Legacy Tools

jlogfmt is designed to be a drop-in replacement for basic log viewing:

```bash
# Instead of journalctl
journalctl -u myservice -f
# Use
jlogs myservice table-follow

# Instead of tail
tail -f /var/log/myservice.log
# Use  
jlogfmt -s myservice -f

# Instead of grep + journalctl
journalctl -u myservice | grep ERROR
# Use
jlogfmt -s myservice -e
```

## 📈 Future Enhancements

With the modular architecture, planned features include:

- **Export Formats**: JSON, CSV, XML output options
- **Filtering**: Advanced field-based filtering
- **Aggregation**: Log metrics and statistics
- **Plugins**: Custom log format parsers
- **Configuration**: User preference files
- **Integration**: Direct ELK stack integration

## 📄 License

MIT License - see LICENSE file for details.

---

**jlogfmt** - Making log analysis beautiful and efficient! 🚀 