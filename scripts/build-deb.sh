#!/usr/bin/env bash
# Build the application package without installing or starting the service.
set -euo pipefail
umask 022
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_NAME="zapret-discord-youtube"
OUTPUT="$REPO_DIR/dist"
INPUTS=""

while (($#)); do
    case "$1" in
        --inputs|--output)
            if (($# < 2)) || [[ -z "$2" || "$2" == --* ]]; then
                echo "Требуется каталог для $1" >&2
                exit 2
            fi
            if [[ "$1" == --inputs ]]; then INPUTS="$2"; else OUTPUT="$2"; fi
            shift 2 ;;
        -h|--help)
            echo "Usage: build-deb.sh [--inputs ARCHIVE_DIR] [--output OUTPUT_DIR]"
            exit 0 ;;
        *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

if ((EUID == 0)); then
    echo "Сборка пакета не требует root." >&2
    exit 1
fi
ARCH="$(dpkg --print-architecture)"
if [[ "$ARCH" != amd64 ]]; then
    echo "Доверенный payload закреплён только для amd64, получено: $ARCH" >&2
    exit 1
fi
PKG_VERSION="$(python3 -B - "$REPO_DIR" <<'PY'
from pathlib import Path
import sys

base = Path(sys.argv[1])
sys.path.insert(0, str(base / "src/lib"))
from version_info import debian_version

try:
    print(debian_version(base))
except ValueError as error:
    sys.exit(str(error))
PY
)"

WORK="$(mktemp -d -t zapret-deb-XXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT
STAGE="$WORK/package"
APP="$STAGE/usr/lib/$PKG_NAME"
DOC="$STAGE/usr/share/doc/$PKG_NAME"
install -d "$APP/runtime" "$DOC" "$STAGE/DEBIAN" "$STAGE/usr/bin" \
    "$STAGE/usr/share/applications" "$STAGE/usr/share/icons/hicolor/scalable/apps"

if [[ -z "$INPUTS" ]]; then
    INPUTS="$WORK/inputs"
    install -d "$INPUTS"
    curl_opts=(--fail --location --silent --show-error --proto '=https'
               --proto-redir '=https' --max-time 120 --max-filesize 33554432)
    curl "${curl_opts[@]}" \
        https://github.com/bol-van/zapret/releases/download/v72.9/zapret-v72.9.tar.gz \
        -o "$INPUTS/zapret-v72.9.tar.gz"
    curl "${curl_opts[@]}" \
        https://codeload.github.com/Flowseal/zapret-discord-youtube/zip/176f56dc3f11ce5915c26abcdde903f93d835b64 \
        -o "$INPUTS/flowseal.zip"
fi
python3 "$SCRIPT_DIR/stage-deb-runtime.py" "$INPUTS" "$APP/runtime" "$DOC"

install -m 644 "$REPO_DIR"/{gui.py,sync.py,install.py} "$APP/"
install -m 755 "$REPO_DIR/service.sh" "$APP/runtime/"
for tree in src custom-strategies; do
    cp -R -- "$REPO_DIR/$tree" "$WORK/$tree"
    find "$WORK/$tree" -type d -name __pycache__ -prune -exec rm -rf -- {} +
    find "$WORK/$tree" -type f -name '*.pyc' -delete
    if [[ -n "$(find "$WORK/$tree" ! -type d ! -type f -print -quit)" ]]; then
        echo "Ссылки и специальные файлы запрещены: $tree" >&2
        exit 1
    fi
    cp -R -- "$WORK/$tree" "$APP/runtime/"
done
cp -R -- "$WORK/src" "$APP/"
rm -- "$APP/runtime/src/gui/bootstrap.py"
install -m 644 "$REPO_DIR/LICENSE" "$DOC/copyright"
install -m 644 "$REPO_DIR/src/desktop/zapret-gui.desktop" "$STAGE/usr/share/applications/"
install -m 644 "$REPO_DIR/src/desktop/zapret-gui.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: bash, python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1 (>= 1.5), systemd, nftables, pkexec | policykit-1 (<< 122), polkitd | policykit-1 (<< 122), curl, ca-certificates, iputils-ping, iproute2, procps, git, util-linux
Maintainer: anntr1k3 <154975524+anntr1k3@users.noreply.github.com>
Homepage: https://github.com/anntr1k3/zapret-discord-youtube-linux
Description: GTK4 interface and packaged runtime for Zapret
 Install or remove the managed systemd service separately from the
 application. Installing the package does not enable or start the service.
EOF

cat > "$STAGE/usr/bin/zapret-gui" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/lib/zapret-discord-youtube/gui.py "$@"
EOF
cat > "$STAGE/usr/bin/zapret" <<'EOF'
#!/bin/sh
runtime=/opt/zapret-discord-youtube/current
if [ ! -x "$runtime/service.sh" ] || [ ! -f "$runtime/.system-install" ]; then
    echo "Управляемый сервис не установлен. Используйте zapret-gui." >&2
    exit 1
fi
exec "$runtime/service.sh" "$@"
EOF

find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
find "$APP" -type f -name '*.sh' -exec chmod 755 {} +
chmod 755 "$APP/runtime/nfqws" "$STAGE/usr/bin/"{zapret,zapret-gui}

# No maintainer scripts: package operations must not touch the managed service.
NAME="${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$WORK/$NAME"
mkdir -p -- "$OUTPUT"
install -m 644 "$WORK/$NAME" "$OUTPUT/$NAME"
sha256sum -- "$OUTPUT/$NAME"
