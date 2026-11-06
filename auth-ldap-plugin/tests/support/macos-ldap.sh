#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the selected macOS tests against a real, isolated Homebrew OpenLDAP server.
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo 'macos-ldap: macOS is required' >&2; exit 1; }
[[ $# -gt 0 ]] || { echo 'macos-ldap: provide the test command' >&2; exit 1; }
brew=$(command -v brew) || { echo 'macos-ldap: Homebrew is required' >&2; exit 1; }
brew_owner=$(stat -f %Su "$(dirname "$(dirname "$brew")")")
brew_command() {
    if [[ $EUID -eq 0 && $brew_owner != root ]]; then
        sudo -H -u "$brew_owner" env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 "$brew" "$@"
    else
        HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 "$brew" "$@"
    fi
}
prefix=$(brew_command --prefix openldap)
if [[ ! -x $prefix/libexec/slapd ]]; then
    brew_command install openldap
fi
slapd=$prefix/libexec/slapd
schema=$(brew_command --prefix)/etc/openldap/schema/core.schema
ldapsearch=$prefix/bin/ldapsearch
ldapadd=$prefix/bin/ldapadd
[[ -x $slapd && -r $schema && -x $ldapsearch && -x $ldapadd ]] || {
    echo 'macos-ldap: the native OpenLDAP server, clients and core schema are required' >&2
    exit 1
}
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/busbar-ldap.XXXXXX")
mkdir "$work/db"
privilege=()
if [[ $EUID -ne 0 ]]; then privilege=(sudo -n); fi
server_pid=
launcher_pid=
cleanup() {
    rc=$?
    trap - EXIT
    if [[ -n $server_pid ]]; then
        ${privilege[@]+"${privilege[@]}"} kill "$server_pid" 2>/dev/null || true
    fi
    # The launcher is slapd in the foreground (-d), under a root sudo unless this runs as root:
    # with no pidfile read it is still running, and only a privileged kill reaches it.
    if [[ -n $launcher_pid ]]; then
        ${privilege[@]+"${privilege[@]}"} kill "$launcher_pid" 2>/dev/null || true
        wait "$launcher_pid" 2>/dev/null || true
    fi
    cat "$work/slapd.log" >&2
    ${privilege[@]+"${privilege[@]}"} rm -rf "$work"
    echo 'macos-ldap: isolated directory stopped and removed' >&2
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
: > "$work/slapd.log"
cat > "$work/slapd.conf" <<EOF
include "$schema"
pidfile "$work/slapd.pid"
argsfile "$work/slapd.args"
database mdb
suffix "dc=example,dc=org"
rootdn "cn=admin,dc=example,dc=org"
rootpw adminpassword
directory "$work/db"
maxsize 10485760
EOF
"$slapd" -VV 2>&1 || true
shasum -a 256 "$work/slapd.conf" >&2
sed '/^rootpw /s/ .*/ [fixture secret]/' "$work/slapd.conf" >&2
# The existing TLS fixture relays to this exact loopback address. No machine-wide
# directory configuration, persistent service or test skip is installed.
${privilege[@]+"${privilege[@]}"} "$slapd" -Tt -u -f "$work/slapd.conf" >> "$work/slapd.log" 2>&1
${privilege[@]+"${privilege[@]}"} "$slapd" -f "$work/slapd.conf" -h ldap://127.0.0.1:389 -d 256 >> "$work/slapd.log" 2>&1 &
launcher_pid=$!
ready=
for _ in {1..100}; do
    if [[ -s $work/slapd.pid ]]; then
        server_pid=$(cat "$work/slapd.pid")
        if ${privilege[@]+"${privilege[@]}"} /usr/sbin/lsof -nP -a -p "$server_pid" \
            -iTCP:389 -sTCP:LISTEN > "$work/ready.log" 2>&1; then ready=1; break; fi
    fi
    ${privilege[@]+"${privilege[@]}"} kill -0 "$launcher_pid" 2>/dev/null || {
        cat "$work/ready.log" >&2 2>/dev/null || true
        echo 'macos-ldap: slapd exited before listening' >&2
        exit 1
    }
    sleep 0.1
done
[[ -n $ready ]] || { echo 'macos-ldap: slapd did not listen on 127.0.0.1:389 in time' >&2; exit 1; }
cat "$work/ready.log" >&2
ps -p "$server_pid" -o pid= -o command= >&2
"$ldapsearch" -x -H ldap://127.0.0.1:389 \
    -D cn=admin,dc=example,dc=org -w adminpassword \
    -b '' -s base supportedLDAPVersion
"$ldapadd" -x -H ldap://127.0.0.1:389 \
    -D cn=admin,dc=example,dc=org -w adminpassword <<'LDIF'
dn: dc=example,dc=org
objectClass: top
objectClass: dcObject
objectClass: organization
dc: example
o: Example Org
LDIF
export BUSBAR_TEST_LDAP_URL=ldap://127.0.0.1:389
"$@"
