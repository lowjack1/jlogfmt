#!/bin/bash

# Install jlogfmt - JSON Log Formatter utilities

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Installing jlogfmt - JSON Log Formatter utilities..."

# Add to ~/.zshrc if not already present
if ! grep -q "# jlogfmt - JSON Log Formatter" ~/.zshrc; then
    echo "" >> ~/.zshrc
    echo "# jlogfmt - JSON Log Formatter aliases" >> ~/.zshrc
    echo "alias jlogs='$PROJECT_DIR/jlogs'" >> ~/.zshrc
    echo "alias jlogfmt='$PROJECT_DIR/jlogfmt'" >> ~/.zshrc
    echo "# Local service aliases" >> ~/.zshrc
    echo "alias jlogs-local='$PROJECT_DIR/jlogs-local'" >> ~/.zshrc
    echo "alias jlogfmt-local='$PROJECT_DIR/jlogfmt-local'" >> ~/.zshrc
    echo "alias jlogs-local-pipe='$PROJECT_DIR/jlogs-local-pipe'" >> ~/.zshrc
    echo "✅ Added aliases to ~/.zshrc"
else
    echo "ℹ️  Aliases already exist in ~/.zshrc"
fi

# Also add to ~/.bashrc if it exists
if [ -f ~/.bashrc ] && ! grep -q "# jlogfmt - JSON Log Formatter" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# jlogfmt - JSON Log Formatter aliases" >> ~/.bashrc
    echo "alias jlogs='$PROJECT_DIR/jlogs'" >> ~/.bashrc
    echo "alias jlogfmt='$PROJECT_DIR/jlogfmt'" >> ~/.bashrc
    echo "# Local service aliases" >> ~/.bashrc
    echo "alias jlogs-local='$PROJECT_DIR/jlogs-local'" >> ~/.bashrc
    echo "alias jlogfmt-local='$PROJECT_DIR/jlogfmt-local'" >> ~/.bashrc
    echo "alias jlogs-local-pipe='$PROJECT_DIR/jlogs-local-pipe'" >> ~/.bashrc
    echo "✅ Added aliases to ~/.bashrc"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Available commands:"
echo ""
echo "🏢 For systemd services:"
echo "  jlogs <service>       - View logs with colors (last hour)"
echo "  jlogs <service> follow        - Follow logs in real-time"
echo "  jlogs <service> errors        - Show only errors and warnings"
echo "  jlogs <service> table         - Beautiful table format (jlogfmt)"
echo "  jlogs <service> table-follow  - Table format following logs (jlogfmt)"
echo ""
echo "  jlogfmt [options]     - Advanced JSON log formatter with full options"
echo ""
echo "🏠 For local services (python3 main.py, golang, etc.):"
echo "  jlogs-local-pipe      - Process piped output"
echo "  jlogs-local <file>    - View log files"
echo "  jlogfmt-local         - Advanced local log formatter"
echo ""
echo "💡 Quick examples:"
echo "  python3 main.py 2>&1 | jlogs-local-pipe"
echo "  go run main.go 2>&1 | jlogs-local-pipe"
echo "  jlogs-local /path/to/app.log follow"
echo ""
echo "🔄 Reload your shell or run: source ~/.zshrc" 