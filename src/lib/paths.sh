#!/usr/bin/env bash

configure_paths() {
    HOME_DIR_PATH="$(realpath -- "$1")" || return 1
    BASE_DIR="$HOME_DIR_PATH"
    CONF_FILE="$BASE_DIR/conf.env"
    USER_LISTS_DIR="$BASE_DIR/user-lists"
    FAKE_DIR="$BASE_DIR/fakes"
    CUSTOM_STRATEGIES_DIR="$BASE_DIR/custom-strategies"
    REPO_DIR="$BASE_DIR/zapret-latest"
    NFQWS_PATH="$BASE_DIR/nfqws"
    SYSTEM_INSTALL=false

    if [[ -f "$BASE_DIR/.system-install" ]]; then
        [[ "$(<"$BASE_DIR/.system-install")" == zapret-system-installer-v1 ]] || return 1
        # /<root>/opt/zapret-discord-youtube/releases/<id>
        INSTALL_ROOT="$(realpath -- "$BASE_DIR/../../../..")" || return 1
        CONF_FILE="${INSTALL_ROOT%/}/etc/zapret-discord-youtube/conf.env"
        USER_LISTS_DIR="${INSTALL_ROOT%/}/etc/zapret-discord-youtube/user-lists"
        FAKE_DIR="${INSTALL_ROOT%/}/etc/zapret-discord-youtube/fakes"
        SYSTEM_INSTALL=true
    fi
}
