#!/bin/bash
# source-only auth loader for BBHUNT_AUTH_HEADERS

[ "${BASH_SOURCE[0]}" = "$0" ] && {
    echo "source me, don't run me" >&2
    return 1 2>/dev/null || exit 1
}

BB_AUTH_ARGS=()
BB_AUTH_SESSION_ID="${BBHUNT_SESSION_ID:-}"

_bb_log() {
    [ -n "${BB_AUTH_DEBUG:-}" ] && echo "[auth] $*" >&2
}

if [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
    declare -a _tmp=()
    _cnt=0 _bad=0

    while IFS= read -r _line; do
        case "$_line" in ''|'#') continue ;; esac
        [[ "$_line" == *$'\r'* ]] && { _bb_log "skip CR: ${_line//$'\r'/\\r}"; ((_bad++)); continue; }
        [[ "$_line" != *":"* ]] && { _bb_log "skip no colon: $_line"; ((_bad++)); continue; }
        _tmp+=(-H "$_line")
        ((_cnt++))
    done <<< "$BBHUNT_AUTH_HEADERS"

    BB_AUTH_ARGS=("${_tmp[@]}")
    [ $_bad -gt 0 ] && _bb_log "skipped $_bad invalid, $_cnt valid"
    unset _tmp _line _cnt _bad

    if [ -z "$BB_AUTH_SESSION_ID" ] && [ ${#BB_AUTH_ARGS[@]} -gt 0 ]; then
        _input=""
        for ((i=1; i<${#BB_AUTH_ARGS[@]}; i+=2)); do
            _input+="${BB_AUTH_ARGS[$i]}"$'\n'
        done
        _input="${_input%$'\n'}"
        _hash=""
        if command -v shasum >/dev/null; then
            _hash=$(printf '%s' "$_input" | shasum -a 256 2>/dev/null | cut -c1-12)
        elif command -v sha256sum >/dev/null; then
            _hash=$(printf '%s' "$_input" | sha256sum 2>/dev/null | cut -c1-12)
        elif command -v cksum >/dev/null; then
            _hash=$(printf '%s' "$_input" | cksum | cut -d' ' -f1 | cut -c1-12)
        fi
        [ -n "$_hash" ] && BB_AUTH_SESSION_ID="$_hash" && export BBHUNT_SESSION_ID="$_hash"
        unset _input _hash
    fi
fi

bb_auth_banner() {
    if [ -n "$BB_AUTH_SESSION_ID" ]; then
        echo "[auth] session=$BB_AUTH_SESSION_ID headers=$(( ${#BB_AUTH_ARGS[@]} / 2 ))"
    else
        echo "[auth] inactive"
    fi
}

bb_auth_active() {
    [ "${#BB_AUTH_ARGS[@]}" -gt 0 ]
}
