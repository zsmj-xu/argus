#!/bin/sh
set -eu

expected_host=$1
operation=$2
[ "$operation" = get ] || exit 0

protocol=
host=
while IFS='=' read -r key value; do
    [ -n "$key" ] || break
    case "$key" in
        protocol) protocol=$value ;;
        host) host=$value ;;
    esac
done

[ "$protocol" = https ] && [ "$host" = "$expected_host" ] || exit 0

token=$(cat "${ARGUS_GITLAB_TOKEN_FILE:-/run/secrets/gitlab_token}")
[ -n "$token" ] || exit 1
case "$token" in
    *'
'*) exit 1 ;;
esac
printf 'password=%s\n' "$token"
