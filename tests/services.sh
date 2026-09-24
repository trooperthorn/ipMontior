#!/usr/bin/env bash
# Start the loopback snmpd and mosquitto the integration tests expect.
# Debian/Ubuntu: apt-get install snmp snmpd mosquitto
set -euo pipefail
dir="$(mktemp -d)"
cat > "$dir/snmpd.conf" <<CONF
rocommunity testcomm 127.0.0.1
createUser v3user SHA "authpass123" AES "privpass123"
rouser v3user priv
CONF
snmpd -C -c "$dir/snmpd.conf" -Lf "$dir/snmpd.log" -p "$dir/snmpd.pid" \
  --persistentDir="$dir" udp:127.0.0.1:1161
mosquitto -p 18830 -d
echo "snmpd on udp/1161 and mosquitto on tcp/18830 started (state in $dir)"
