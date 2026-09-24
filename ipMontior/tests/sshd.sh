#!/usr/bin/env bash
# Loopback sshd for the Linux and Docker tests. Run as root (it creates a
# throwaway user). Debian/Ubuntu: apt-get install openssh-server
#   sshd       127.0.0.1:2222, user "wptest", key /tmp/wp-ssh/client_ed25519,
#              password "wp-test-pass-1", known_hosts /tmp/wp-ssh/known_hosts
#   docker     /tmp/wp-ssh/docker is a fake CLI (tests/fixtures/fake-docker)
set -euo pipefail
d=/tmp/wp-ssh
mkdir -p "$d" /run/sshd
chmod 755 "$d"
id wptest >/dev/null 2>&1 || useradd -m -s /bin/bash wptest
echo 'wptest:wp-test-pass-1' | chpasswd
[ -f "$d/host_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$d/host_ed25519"
[ -f "$d/client_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$d/client_ed25519"
home="$(getent passwd wptest | cut -d: -f6)"
install -d -m 700 -o wptest -g wptest "$home/.ssh"
install -m 600 -o wptest -g wptest "$d/client_ed25519.pub" "$home/.ssh/authorized_keys"
chmod 644 "$d/client_ed25519"   # test key only; readable by the unprivileged test runner
install -m 755 "$(dirname "$0")/fixtures/fake-docker" "$d/docker"
echo 0 > "$d/web-restarts"; chmod 666 "$d/web-restarts"
cat > "$d/sshd_config" <<CONF
Port 2222
ListenAddress 127.0.0.1
HostKey $d/host_ed25519
PidFile $d/sshd.pid
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
StrictModes no
AllowUsers wptest
CONF
[ -f "$d/sshd.pid" ] && kill "$(cat "$d/sshd.pid")" 2>/dev/null || true
/usr/sbin/sshd -f "$d/sshd_config"
echo "[127.0.0.1]:2222 $(cut -d' ' -f1,2 "$d/host_ed25519.pub")" > "$d/known_hosts"
chmod 644 "$d/known_hosts"
echo "sshd on 127.0.0.1:2222 ready (state in $d)"
