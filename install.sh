#!/bin/sh
set -eu

REPO=${OUTWAY_REPO:-xiaozhou26/outway}
INSTALL_DIR=${OUTWAY_INSTALL_DIR:-/usr/local/bin}
VERSION=${OUTWAY_VERSION:-latest}
BINARY_NAME=outway

log() {
    printf '%s\n' "$*"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

can_write_install_dir() {
    path=$INSTALL_DIR
    while [ ! -e "$path" ]; do
        parent=$(dirname "$path")
        [ "$parent" != "$path" ] || break
        path=$parent
    done
    [ -d "$path" ] && [ -w "$path" ]
}

run_privileged() {
    if can_write_install_dir || [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        fail "$INSTALL_DIR is not writable; run as root or install sudo"
    fi
}

uninstall() {
    target=$INSTALL_DIR/$BINARY_NAME
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        log "$BINARY_NAME is not installed at $target"
        return
    fi

    run_privileged rm -f "$target"
    log "Removed $target"
}

detect_target() {
    case "$(uname -s)" in
        Linux) os=linux ;;
        Darwin) os=darwin ;;
        *) fail "unsupported operating system: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac

    printf '%s-%s' "$os" "$arch"
}

download() {
    url=$1
    output=$2

    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 15 -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$output" "$url"
    else
        fail "curl or wget is required"
    fi
}

install_latest() {
    command -v tar >/dev/null 2>&1 || fail "tar is required"

    target=$(detect_target)
    asset=$BINARY_NAME-$target
    archive=$asset.tar.gz

    case "$VERSION" in
        latest)
            url=https://github.com/$REPO/releases/latest/download/$archive
            ;;
        v*)
            url=https://github.com/$REPO/releases/download/$VERSION/$archive
            ;;
        *)
            url=https://github.com/$REPO/releases/download/v$VERSION/$archive
            ;;
    esac

    tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t outway-install)
    trap 'rm -rf "$tmp_dir"' 0
    trap 'exit 1' HUP INT TERM

    log "Downloading $url"
    download "$url" "$tmp_dir/$archive"
    tar -xzf "$tmp_dir/$archive" -C "$tmp_dir" "$asset"

    run_privileged mkdir -p "$INSTALL_DIR"
    run_privileged install -m 0755 "$tmp_dir/$asset" "$INSTALL_DIR/$BINARY_NAME"

    "$INSTALL_DIR/$BINARY_NAME" --help >/dev/null
    log "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
}

case "${1:-install}" in
    install) install_latest ;;
    uninstall|remove) uninstall ;;
    *) fail "usage: install.sh [install|uninstall]" ;;
esac
