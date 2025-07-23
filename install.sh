#!/bin/bash

# Install jlogfmt - JSON Log Formatter utilities

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Installing jlogfmt - JSON Log Formatter utilities..."

# Add to ~/.zshrc if not already present
if ! grep -q "# jlogfmt - JSON Log Formatter" ~/.zshrc; then
    echo "" >> ~/.zshrc
    echo "# jlogfmt - JSON Log Formatter aliases" >> ~/.zshrc
    echo "alias jlogs='$PROJECT_DIR/jlogs'" >> ~/.zshrc
    echo "alias jlogfmt='$PROJECT_DIR/jlogfmt'" >> ~/.zshrc
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
    echo "✅ Added aliases to ~/.bashrc"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Available commands:"
echo "  jlogs                 - View logs with colors (last hour)"
echo "  jlogs follow          - Follow logs in real-time"
echo "  jlogs errors          - Show only errors and warnings"
echo "  jlogs table           - Beautiful table format (jlogfmt)"
echo "  jlogs table-follow    - Table format following logs (jlogfmt)"
echo ""
echo "  jlogfmt [options]     - Advanced JSON log formatter with full options"
echo ""
echo "🔄 Reload your shell or run: source ~/.zshrc" 