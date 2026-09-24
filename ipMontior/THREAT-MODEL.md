# Threat model

watchpost holds credentials that can read most of the lab (SNMP v3 users,
a WinRM account, an MQTT account) and exposes an inventory of what is
monitored. Those are the assets. Each control below is labelled
**enforced** (the code or container prevents it) or **advisory** (it depends
on how you deploy).

## Trust boundaries

1. **Config and secrets to process.** YAML is mounted read-only; secrets come
   from environment variables or files under `/run/secrets`.
2. **Process to monitored devices.** Outbound SNMP, WinRM, MQTT, HTTP, DNS,
   ICMP, and TCP. Devices are treated as untrusted data sources.
3. **Dashboard to browser.** Inbound HTTP on 8080.
4. **Process to alert targets.** Outbound to ntfy, webhook, SMTP, MQTT.

## Controls

| Control | Status | Notes |
|---|---|---|
| No write endpoints in the web surface | enforced | Monitors, alerts, and credentials can only change by editing YAML and restarting. A dashboard compromise can read inventory, not mute alerts. |
| Unresolved secret reference fails startup | enforced | Prevents silently running with an empty community or password. |
| Unknown config keys rejected | enforced | Typos such as `verfy_tls: false` fail loudly instead of being ignored. |
| Credential type must match monitor type | enforced | A WinRM secret can not be sent as an SNMP community by mistake. |
| TLS validation on by default (HTTP, TLS cert, WinRM, MQTT TLS) | enforced | Turning it off is an explicit per-monitor setting. |
| Device-supplied text rendered as text | enforced | `app.js` uses `textContent` only; CSP forbids inline script and third-party origins. Covers hostile SNMP strings, MQTT payloads, HTTP error text. |
| PowerShell injection from config values | enforced | Values are embedded as single-quoted literals with quotes doubled; `disk` is pattern-validated. Tested in `test_windows.py`. |
| Secrets redacted from SNMP error text | enforced | Tested with a wrong community. |
| Container: non-root UID 10001, all capabilities dropped, read-only root, no-new-privileges | enforced by compose | Only if you run it with the provided compose file. |
| Unprivileged ICMP instead of CAP_NET_RAW | enforced by compose | Via the `net.ipv4.ping_group_range` sysctl, namespaced to the container. |
| Dashboard basic auth | advisory | Off unless configured. Constant-time comparison. Basic auth over plain HTTP is readable on the wire; put a TLS reverse proxy in front or bind to a management VLAN. |
| Dependency suppression can hide a real outage | advisory | A wrong `depends_on` (a server marked behind a switch it does not use) suppresses that server's alerts whenever the switch is down. Suppression is always recorded in the event log with the blocking monitor's name, and cycles and unknown parents are rejected at load. Review dependencies like firewall rules. |
| Network exposure of 8080 | advisory | Compose publishes on all interfaces by default; bind to one address if needed. |

## Discovery

Discovery sends credentials to addresses it has not seen before, which is a
different risk from polling known hosts. Controls:

| Control | Status | Notes |
|---|---|---|
| Only named credentials are tried, in the order listed | enforced | `discovery.credentials` must reference existing entries; nothing else is sent. |
| WinRM credentials only after the listener's certificate validates for the host's DNS name | enforced | A rogue or compromised host inside the range could otherwise run a WinRM listener to collect an NTLM exchange for offline cracking or relay. With validation, it would also need a certificate your CA issued for that name. `winrm_require_valid_tls: false` turns this off; do not, unless the range is fully trusted. |
| Rejected WinRM credential retired after `max_auth_failures` | enforced | Attempts with a credential are serialised until it succeeds once, so parallel scanning can not overshoot the limit (tested with 12 concurrent hosts). Keeps a wrong password from walking a domain account into lockout. |
| Target size capped (`max_hosts`) and computed before expansion | enforced | |
| Discovery never edits the running config | enforced | Output is a proposal file for review. |
| SNMP v2c communities are sent in cleartext to every address in range | advisory | Inherent to v2c. Prefer v3 credentials for discovery, list v2c last, or scope v2c discovery to the device subnet that needs it. |
| SNMP v3 probes to unknown hosts | advisory | A listener can capture the authenticated request and attempt an offline guess of the auth passphrase. Use long random passphrases. |
| SSH host keys verified for every monitor | enforced | No monitor-level option disables it. Agent use and agent forwarding are off, so a compromised host can not use keys from the watchpost machine. |
| Discovery trust-on-first-use offers key credentials only | enforced | A public-key signature is bound to the session and gives an impostor nothing reusable; a password would. Password credentials are only used against hosts whose key is already trusted. First-seen keys are listed for review, not silently added. |
| Changed or unparseable known_hosts entry stops SSH for that host | enforced | asyncssh skips malformed lines silently; discovery checks the file text so a corrupted entry is not mistaken for no entry. |
| Rejected SSH credential retired after `max_auth_failures` | enforced | Same serialisation as WinRM. Protects against account lockout and fail2ban bans of the watchpost host. |
| Shell injection through config values | enforced | Mount, unit, container, and docker command are pattern-validated at load and shlex-quoted when sent. Tested with metacharacters in each. The `command` field of `linux` monitors is run as written: it is code you chose to run, like a cron entry. |
| Docker checks read no container config | enforced | Only State and RestartCount are requested, so environment variables (often secrets) never cross the wire. |
| LDAPS only, chain and hostname validated | enforced | ldap3 `Tls(validate=CERT_REQUIRED)` with its post-handshake hostname check. Simple bind inside TLS; no plain LDAP option. |
| Docker access is root-equivalent on the host | advisory | Anyone who can run `docker` can start a privileged container. Instead of adding the account to the `docker` group, grant only what watchpost runs and set `docker_command: "sudo -n docker"`: `watchpost ALL=(root) NOPASSWD: /usr/bin/docker ps *, /usr/bin/docker inspect *`. Sudo argument wildcards match across spaces, so this still allows any `ps` or `inspect` arguments; both are read-only, but `inspect` without `--format` can show container environment variables. |
| Directory account scope | advisory | Use a dedicated account with no rights beyond default authenticated read. It can read most of the directory by default; that is AD's model, not something watchpost can narrow. |
| TrueNAS, Proxmox, vSphere credentials only over validated TLS during discovery | enforced | `api_require_valid_tls` (default on). An appliance's self-signed certificate is captured with its fingerprint for you to verify and pin; nothing is sent until then. Monitors verify by default too. |
| vSphere unauthenticated fingerprint | enforced | Discovery identifies ESXi/vCenter from the public `/sdk/vimServiceVersions.xml` before any login, so vSphere passwords are never tried against non-vSphere hosts. |
| vSphere sessions are closed every poll | enforced | Login and logout in a `finally`; leaked sessions would exhaust ESXi's session limit. |
| Plain-HTTP tokens (Home Assistant, Technitium) | advisory | Both default to HTTP. A monitor with `https: false` sends its bearer token in cleartext on every poll, readable by anything on the path. Discovery refuses unless `api_require_valid_tls: false`. Prefer TLS on both; otherwise keep the path on a trusted segment and scope each token to a read-only user. |
| Technitium token kept out of URLs | enforced | Sent as a Bearer header by default; the legacy `?token=` form (which ends up in access logs) is opt-in per monitor. |
| API keys reach only hosts you vouched for, not only the intended product | advisory | With validated TLS, a credential is offered to a host whose identity your CA or a pinned certificate vouches for. That proves who the host is, not what it runs: a UniFi key could be offered to your TrueNAS box during discovery. vSphere is fingerprinted unauthenticated first; TrueNAS keys are sent only after a WebSocket upgrade at /api/current succeeds. Scope discovery targets if this matters. |
| Least-privilege platform accounts | advisory | TrueNAS: a dedicated user with READONLY_ADMIN. Proxmox: a user with PVEAuditor at `/` and a token (tokens can be revoked without touching the user). vSphere: a local or SSO user with the built-in Read-only role. Home Assistant: a dedicated non-admin user's token. UniFi: a key created by a view-only admin. Technitium: a user with only Dashboard: View. None of the checks write anything. |
| Scanning can trip IDS/IPS and host firewalls | advisory | Run it against ranges you own, and expect alerts if you monitor for scans. |

## Accepted risks

**SNMP secrets in process arguments.** The net-snmp tools take the community
or v3 passphrases as argv, readable from `/proc/<pid>/cmdline` for the life of
each poll by anything in the same PID namespace. The container runs only
watchpost, and host root can already read the container's environment and
memory, so this does not add an attacker class. Reconsider if you run other
processes in the container.

**Secrets in memory and environment.** Resolved secrets live in the process
for its lifetime. Use `${file:...}` references to keep them out of
`docker inspect` output, which shows environment variables.

**SQLite history is plaintext.** It holds hostnames, check messages, and
values, not credentials. Protect `./data` like the config.

**Alert payloads leave the lab.** A public ntfy topic or webhook receives
monitor names and messages. Use a self-hosted or authenticated target if that
matters.

## Least privilege for monitoring accounts (advisory)

- SNMP: a v3 user with a read-only view scoped to the MIB subtrees you poll.
- WinRM: a dedicated domain account, not an administrator, granted remote
  management access and CIM read rights on the target classes, and denied
  interactive logon. Certificate mapping removes the password entirely.
- MQTT: an account with ACLs limited to subscribing to the topics you check
  and publishing under the alert `topic_prefix`.
