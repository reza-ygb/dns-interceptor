#!/bin/bash

# DNS Interceptor - Professional Network Security Tool
# One-line installation script

set -e

echo "🔥 DNS Interceptor - Professional Installation 🔥"
echo "================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  Do not run installation as root (sudo will be used when needed)"
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

echo "🖥️  Detected OS: $OS"

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.8"

if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "✅ Python $PYTHON_VERSION detected"
else
    echo "❌ Python 3.8+ required (found $PYTHON_VERSION)"
    exit 1
fi

# Install directory
INSTALL_DIR="$HOME/.local/share/dns-interceptor"
BIN_DIR="$HOME/.local/bin"
VENV_DIR="$INSTALL_DIR/venv"

echo "📁 Installation directory: $INSTALL_DIR"

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Download main script with fallback to Release asset
echo "📥 Downloading DNS Interceptor..."
if ! curl -fsSL "https://raw.githubusercontent.com/reza-ygb/dns-interceptor/master/dns_interceptor.py" -o "$INSTALL_DIR/dns_interceptor.py"; then
    echo "⚠️  Raw download failed, trying GitHub Release asset..."
    if ! curl -fsSL "https://raw.githubusercontent.com/reza-ygb/dns-interceptor/master/dns_interceptor.py" -o /dev/null; then
        echo "ℹ️  Falling back to: https://github.com/reza-ygb/dns-interceptor/releases/download/v2.0.1/dns_interceptor.py"
    fi
    curl -fL "https://github.com/reza-ygb/dns-interceptor/releases/download/v2.0.1/dns_interceptor.py" -o "$INSTALL_DIR/dns_interceptor.py"
fi

# Download requirements with fallback
if ! curl -fsSL "https://raw.githubusercontent.com/reza-ygb/dns-interceptor/master/requirements.txt" -o "$INSTALL_DIR/requirements.txt"; then
    echo "⚠️  Raw requirements download failed, trying GitHub Release asset..."
    echo "ℹ️  Falling back to: https://github.com/reza-ygb/dns-interceptor/releases/download/v2.0.1/requirements.txt"
    curl -fL "https://github.com/reza-ygb/dns-interceptor/releases/download/v2.0.1/requirements.txt" -o "$INSTALL_DIR/requirements.txt"
fi

# Make executable
chmod +x "$INSTALL_DIR/dns_interceptor.py"

# Create virtual environment and install dependencies (PEP 668 friendly)
echo "📦 Installing Python dependencies..."
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Create wrapper script
echo "🔧 Creating system command..."
cat > "$BIN_DIR/dns-interceptor" << 'EOF'
#!/bin/bash

# DNS Interceptor wrapper script
INSTALL_DIR="$HOME/.local/share/dns-interceptor"
VENV_DIR="$INSTALL_DIR/venv"

# Check if running as root for network operations
if [[ $EUID -ne 0 ]] && [[ "$*" != *"--help"* ]] && [[ "$*" != *"-h"* ]]; then
    echo "⚠️  Network operations require root privileges"
    echo "💡 Run with: sudo dns-interceptor [options]"
    echo "📖 For help: dns-interceptor --help"
    exit 1
fi

# Execute main script via venv python (preserve HOME under sudo)
if [[ -n "$SUDO_USER" ]]; then
    export HOME="/home/$SUDO_USER"
fi
exec "$VENV_DIR/bin/python" "$INSTALL_DIR/dns_interceptor.py" "$@"
EOF

chmod +x "$BIN_DIR/dns-interceptor"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "🔗 Adding to PATH..."
    
    # Add to bashrc/zshrc
    for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [[ -f "$rcfile" ]]; then
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$rcfile"
            echo "✅ Added to $rcfile"
        fi
    done
    
    # Export for current session
    export PATH="$BIN_DIR:$PATH"
fi

# Create desktop entry (Linux only)
if [[ "$OS" == "linux" ]]; then
    DESKTOP_DIR="$HOME/.local/share/applications"
    mkdir -p "$DESKTOP_DIR"
    
    cat > "$DESKTOP_DIR/dns-interceptor.desktop" << EOF
[Desktop Entry]
Name=DNS Interceptor
Comment=Professional Network Security Analysis Tool
Exec=gnome-terminal -- sudo dns-interceptor --help
Icon=network-wired
Terminal=true
Type=Application
Categories=System;Security;Network;
EOF
    
    echo "🖥️  Desktop entry created"
fi

# Installation complete
echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
echo "🚀 Quick Start:"
echo "  dns-interceptor --help                    # Show help"
echo "  sudo dns-interceptor -i eth0 --discovery-only    # Network discovery"
echo "  sudo dns-interceptor -i eth0 --intercept-only    # Passive monitoring"
echo ""
echo "📚 Documentation:"
echo "  https://github.com/reza-ygb/dns-interceptor"
echo ""
echo "⚠️  Remember:"
echo "  • Root privileges required for network operations"
echo "  • Use only on authorized networks"
echo "  • Follow ethical hacking guidelines"
echo ""
echo "💡 Restart your terminal or run: source ~/.bashrc (یا برای zsh: source ~/.zshrc)"

# Test installation
echo "🧪 Testing installation..."
if command -v dns-interceptor >/dev/null 2>&1; then
    echo "✅ dns-interceptor command available"
    dns-interceptor --help | head -5
else
    echo "⚠️  Command not found - restart terminal or source ~/.bashrc"
fi

echo ""
echo "🔥 DNS Interceptor v2.0.0 installed successfully!"
