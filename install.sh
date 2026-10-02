#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/protocol-rwp/ReWeb"
BOOTSTRAP_PEER="24.144.109.255:5000"

usage() {
    cat <<EOF
Usage: ./install.sh [browser|server|all] [options]

  browser     install the ReWeb browser (default)
  server      install what's needed to run a ReWeb server
  all         both

Options:
  -y, --yes       don't ask before installing system packages
  --dry-run       show what would be done without changing anything
  -h, --help      show this help
EOF
}

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

MODE=browser
ASSUME_YES=0
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        browser|server|all) MODE=$arg ;;
        -y|--yes) ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown option: $arg" ;;
    esac
done

run() {
    if [ "$DRY_RUN" = 1 ]; then
        echo "  would run: $*"
    else
        "$@"
    fi
}

want_browser() { [ "$MODE" = browser ] || [ "$MODE" = all ]; }
want_server() { [ "$MODE" = server ] || [ "$MODE" = all ]; }

[ "$(uname -s)" = Linux ] || die "this script supports Linux only for now."

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/rwp.py" ]; then
    DIR="$SCRIPT_DIR"
else
    DIR="${REWEB_DIR:-$HOME/reweb}"
    if [ ! -f "$DIR/rwp.py" ]; then
        command -v git >/dev/null || die "git is needed to download ReWeb. Install git and run this again."
        say "Downloading ReWeb into $DIR"
        run git clone --depth 1 "$REPO_URL" "$DIR"
    fi
fi
say "Installing ReWeb $MODE in $DIR"

OS_RELEASE="${OS_RELEASE_FILE:-/etc/os-release}"
[ -r "$OS_RELEASE" ] || die "can't read $OS_RELEASE to detect your Linux distribution."
DISTRO_ID=$(. "$OS_RELEASE"; echo "${ID:-}")
DISTRO_LIKE=$(. "$OS_RELEASE"; echo "${ID_LIKE:-}")
DISTRO_NAME=$(. "$OS_RELEASE"; echo "${PRETTY_NAME:-$ID}")

FAMILY=""
for id in $DISTRO_ID $DISTRO_LIKE; do
    case "$id" in
        debian|ubuntu) FAMILY=apt; break ;;
        fedora|rhel|centos) FAMILY=dnf; break ;;
        arch) FAMILY=pacman; break ;;
    esac
done

PACKAGES=()
case "$FAMILY" in
    apt)
        PACKAGES+=(python3 python3-venv python3-pip python3-cryptography)
        want_browser && PACKAGES+=(python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1)
        want_server && PACKAGES+=(nodejs php-cgi)
        INSTALL=(apt-get install -y)
        REFRESH=(apt-get update)
        ;;
    dnf)
        PACKAGES+=(python3 python3-pip python3-cryptography)
        want_browser && PACKAGES+=(python3-gobject gtk3 webkit2gtk4.1)
        want_server && PACKAGES+=(nodejs php-cli)
        INSTALL=(dnf install -y)
        REFRESH=()
        ;;
    pacman)
        PACKAGES+=(python python-pip python-cryptography)
        want_browser && PACKAGES+=(python-gobject gtk3 webkit2gtk-4.1)
        want_server && PACKAGES+=(nodejs php-cgi)
        INSTALL=(pacman -S --needed --noconfirm)
        REFRESH=()
        ;;
    *)
        warn "$DISTRO_NAME isn't supported by this script yet."
        echo "Install these yourself, then run this script again with the same options:"
        echo "  Python 3 (with venv), the Python 'cryptography' package"
        want_browser && echo "  GTK 3, WebKit2GTK 4.1, and the Python GObject bindings (PyGObject)"
        want_server && echo "  Node.js and php-cgi (only needed for .rws and .php pages)"
        exit 1
        ;;
esac

SUDO=()
if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null || die "installing packages needs root. Run this as root or install sudo."
    SUDO=(sudo)
fi

say "System packages for $DISTRO_NAME:"
echo "  ${PACKAGES[*]}"
if [ "$ASSUME_YES" != 1 ] && [ "$DRY_RUN" != 1 ]; then
    printf 'Install them now? [Y/n] '
    read -r answer </dev/tty || answer=n
    case "$answer" in
        ""|y|Y|yes|YES) ;;
        *) die "cancelled. Nothing was installed." ;;
    esac
fi
if [ "${#REFRESH[@]}" -gt 0 ]; then
    run "${SUDO[@]}" "${REFRESH[@]}"
fi
run "${SUDO[@]}" "${INSTALL[@]}" "${PACKAGES[@]}"

VENV="$DIR/.venv"
PY="$VENV/bin/python"
say "Setting up the Python environment in $VENV"
if [ ! -x "$PY" ]; then
    run python3 -m venv --system-site-packages "$VENV"
fi
if [ "$DRY_RUN" != 1 ]; then
    "$PY" -c "import cryptography" 2>/dev/null || "$PY" -m pip install --quiet cryptography
fi
if want_browser; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "  would run: $PY -m pip install pywebview"
    else
        "$PY" -c "import webview" 2>/dev/null || "$PY" -m pip install --quiet pywebview
    fi
fi

make_launcher() {
    local name=$1 script=$2
    local path="$DIR/$name"
    if [ "$DRY_RUN" = 1 ]; then
        echo "  would create $path"
        return
    fi
    cat > "$path" <<EOF
#!/bin/sh
cd "$DIR" && exec "$PY" $script "\$@"
EOF
    chmod +x "$path"
    if [ -d "$HOME/.local/bin" ]; then
        ln -sf "$path" "$HOME/.local/bin/$name"
    fi
}

if want_browser; then
    say "Setting up the browser"
    make_launcher reweb-browser browser.py
    if [ ! -f "$DIR/dns_peers.json" ]; then
        echo "  adding $BOOTSTRAP_PEER as a DNS peer, so the browser can find sites"
        run "$PY" "$DIR/dnsroots.py" peer "$BOOTSTRAP_PEER"
    fi
    if [ "$DRY_RUN" != 1 ] && [ -d "$HOME/.local/share/applications" ]; then
        cat > "$HOME/.local/share/applications/reweb-browser.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=ReWeb Browser
Comment=Browse the ReWeb
Exec=$DIR/reweb-browser
Terminal=false
Categories=Network;WebBrowser;
EOF
    fi
fi

if want_server; then
    say "Setting up the server"
    make_launcher reweb-server server.py
    if [ ! -d "$DIR/www" ]; then
        run mkdir -p "$DIR/www"
        if [ "$DRY_RUN" != 1 ]; then
            cat > "$DIR/www/index.html" <<'EOF'
<!DOCTYPE html>
<html><head><title>My ReWeb site</title></head>
<body><h1>It works!</h1><p>Put your pages in the <code>www</code> folder.</p></body></html>
EOF
        fi
    fi
fi

if [ "$DRY_RUN" != 1 ]; then
    say "Checking the install"
    "$PY" -c "import cryptography" || die "the Python 'cryptography' package isn't working."
    if want_browser; then
        "$PY" -c "import gi; gi.require_version('WebKit2', '4.1'); from gi.repository import WebKit2" \
            || die "WebKit2GTK 4.1 isn't available to Python. Check the system packages above installed correctly."
        "$PY" -c "import webview" || die "pywebview didn't install."
    fi
    if want_server; then
        command -v node >/dev/null || warn "Node.js not found: .rws pages won't run."
        command -v php-cgi >/dev/null || warn "php-cgi not found: .php pages won't run."
    fi
fi

echo
say "Done!"
on_path() { case ":$PATH:" in *":$HOME/.local/bin:"*) [ -d "$HOME/.local/bin" ] ;; *) false ;; esac; }
if want_browser; then
    if on_path; then
        echo "Start the browser:  reweb-browser   (or find 'ReWeb Browser' in your app menu)"
    else
        echo "Start the browser:  $DIR/reweb-browser"
    fi
fi
if want_server; then
    if on_path; then start=reweb-server; else start="$DIR/reweb-server"; fi
    cat <<EOF
Run a server:
  1. Set HOST and PORT near the top of $DIR/server.py
     (HOST is the address to listen on, e.g. your public IP)
  2. Put your site in $DIR/www/
  3. Start it:  $start
     It prints its TLS fingerprint on startup.
  4. Get a name: ask the operator of a TLD, or request one at reweb.rws/request.html
  To run your own TLD instead, see "Claiming a TLD" in README.md.
EOF
fi
