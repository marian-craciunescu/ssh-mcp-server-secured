# SSH MCP Server (Secured)

[![npm version](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured.svg)](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured)
[![CI/CD](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml/badge.svg)](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **secured** fork of [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) with command whitelist/blacklist filtering, network device support, and bulk connection management for safe remote server management via MCP (Model Context Protocol).

## Key Features

* **One-Shot Execution**: `ssh_run` connects, runs a command, and disconnects in a single tool call — no connectionId to pass around
* **Command Whitelist/Blacklist**: Control which commands can be executed
* **Dangerous Pattern Detection**: Blocks fork bombs, command injection, and destructive patterns
* **Network Device Support**: Cisco, Juniper, MikroTik, FortiGate, Palo Alto, Sophos with persistent shell sessions and automatic pager suppression
* **Jump Shell Support**: SSH into a host then enter a nested CLI (telnet to a host, FreeSWITCH fs_cli, etc.) — commands execute inside the nested shell, with an ordered fallback list of jump commands
* **Bulk Connection Management**: Load dozens of connections from CSV/JSON files
* **Environment Variable Credentials**: Passwords auto-resolved from env vars by connectionId — no secrets in chat
* **Multi-Connection Execution**: Run commands across all or selected connections simultaneously
* **Connection Health Monitoring**: Keepalive tracking, dead connection detection, auto-cleanup
* **Configurable Security Policies**: Via config file or environment variables
* **Audit Logging**: Log all blocked command attempts

## Installation

### Quick Setup (Recommended)

```bash
# Add to Claude CLI
claude mcp add ssh-mcp-secured npx '@marian-craciunescu/ssh-mcp-server-secured@latest'
```

### Manual Installation

```bash
npm install -g @marian-craciunescu/ssh-mcp-server-secured
```

```json
{
  "mcpServers": {
    "ssh-mcp-secured": {
      "command": "ssh-mcp-server-secured"
    }
  }
}
```

## Usage

### 1. Single Connection

Connect to a host using `ssh_connect`. You only need to provide host, username, and connectionId — the password is automatically resolved from environment variables:

```
Connect to host 172.168.0.2 with user admin connectionId=router1
```

The LLM calls `ssh_connect` with:

```json
{
  "host": "172.168.0.2",
  "username": "admin",
  "deviceType": "cisco",
  "connectionId": "router1"
}
```

**No password in the tool call.** The server automatically looks up `ROUTER1_PASSWORD` from environment variables.

#### Credential Resolution Convention

The connectionId is converted to an env var prefix: uppercased, non-alphanumeric characters replaced with `_`.

| connectionId | Env var for password | Env var for enable password |
|---|---|---|
| `router1` | `ROUTER1_PASSWORD` | `ROUTER1_ENABLE_PASSWORD` |
| `my-connection` | `MY_CONNECTION_PASSWORD` | `MY_CONNECTION_ENABLE_PASSWORD` |
| `dc1.switch.3` | `DC1_SWITCH_3_PASSWORD` | `DC1_SWITCH_3_ENABLE_PASSWORD` |

Optionally, `<PREFIX>_USERNAME` is also resolved if username is not provided.

Set credentials in your MCP configuration:

```json
{
  "mcpServers": {
    "ssh-mcp-secured": {
      "command": "ssh-mcp-server-secured",
      "env": {
        "SSH_FILTER_MODE": "blacklist",
        "ROUTER1_PASSWORD": "admin123",
        "ROUTER1_ENABLE_PASSWORD": "enable123",
        "SERVER1_PASSWORD": "rootpass",
        "SERVER1_USERNAME": "root"
      }
    }
  }
}
```

Credentials live in the MCP config (or are injected via CI/CD, vault, etc.) and **never appear in chat or tool calls**. If a password is explicitly provided in the tool call, it takes precedence over the env var.



#### SSH Options for Legacy Devices

When connecting to older devices that require non-default algorithms (the equivalent of `ssh -o`), use the `sshOptions` parameter:

In natural language:
>`Connect to 10.0.0.1 port 2222 as user, connectionId old-switch, with KexAlgorithms +diffie-hellman-group-exchange-sha1 and HostKeyAlgorithms +ssh-rsa`

```json
{
  "host": "10.0.0.1",
  "port": 2222,
  "username": "admin",
  "connectionId": "old-switch",
  "sshOptions": {
    "KexAlgorithms": "+diffie-hellman-group-exchange-sha1",
    "HostKeyAlgorithms": "+ssh-rsa"
  }
}
```

This is equivalent to:

```bash
ssh -p 2222 admin@10.0.0.1 -o KexAlgorithms=+diffie-hellman-group-exchange-sha1 -o HostKeyAlgorithms=+ssh-rsa
```
**_Prefix a value with `+` to append to ssh2 defaults. Without `+`, the value replaces the defaults entirely._**



| Option | SSH2 equivalent | Use case |
|--------|-----------------|----------|
| `KexAlgorithms` | `algorithms.kex` | Legacy key exchange (e.g. `diffie-hellman-group1-sha1`) |
| `HostKeyAlgorithms` | `algorithms.serverHostKey` | Legacy host keys (e.g. `ssh-rsa`, `ssh-dss`) |
| `Ciphers` | `algorithms.cipher` | Legacy ciphers (e.g. `aes128-cbc`) |
| `MACs` | `algorithms.hmac` | Legacy MACs (e.g. `hmac-sha1`) |

`sshOptions` is supported on `ssh_connect`, `ssh_connect_with_jump_command`, and JSON files loaded via `ssh_load_connections`.

**Keyboard-interactive auth** is enabled automatically (`tryKeyboard: true`). Legacy devices that reject standard password auth and require `keyboard-interactive` will work without any extra configuration.

### 2. Bulk Connections from File

Load multiple connections from a CSV or JSON file using `ssh_load_connections`. Passwords are resolved from env vars using the same connectionId convention:

**CSV format** (`connections.csv`):

```csv
host,username,port,deviceType,connectionId
172.168.0.2,admin,22,cisco,router1
10.1.2.15,noc,22,cisco,router2
192.168.1.1,root,22,linux,server1
```

No passwords in the file. The server resolves `ROUTER1_PASSWORD`, `ROUTER2_PASSWORD`, `SERVER1_PASSWORD` from env vars.

>**NOTE**: CSV can't carry objects so SSH options for legacy devices must be set via individual env vars or in JSON file.


**JSON format** (`connections.json`):

```json
[
  {
    "host": "172.168.0.2",
    "username": "admin",
    "deviceType": "cisco",
    "connectionId": "router1"
  },
  {
    "host": "10.1.2.15",
    "username": "noc",
    "deviceType": "cisco",
    "connectionId": "router2",
    "sshOptions": {
      "KexAlgorithms": "+diffie-hellman-group-exchange-sha1",
      "HostKeyAlgorithms": "+ssh-rsa"
    }
  }
]
```

**Profiles:**
Define reusable connection profiles for connecting to the same type of device with similar settings (e.g. all Cisco switches).
Profiles can include default SSH options for legacy devices, so you don't have to repeat them in every connection.


***Resolution priority:*** explicit args > profile env vars > connectionId env vars

````bash
export PROFILE_CISCO_USER=admin
export PROFILE_CISCO_PASSWORD=secret123
export PROFILE_CISCO_DEVICE_TYPE=cisco
export PROFILE_CISCO_PORT=2222
export PROFILE_CISCO_SSH_OPTIONS='{"KexAlgorithms":"+diffie-hellman-group-exchange-sha1","HostKeyAlgorithms":"+ssh-rsa"}'
````
BELOW is an example of how profile env vars are resolved when loading connections from CSV/JSON. The `PROFILE_CISCO_SSH_OPTIONS` value is parsed as JSON and applied to all connections with `deviceType` of `cisco`.

| Env Var  Example              | Field                       |Value                  |
| ----------------------------- | --------------------------- |-----------------------|
| PROFILE_CISCO_USER            | username                    | admin                 |
| PROFILE_CISCO_PASSWORD        | password                    | secret123|
| PROFILE_CISCO_DEVICE_TYPE     | deviceType                  | cisco|
| PROFILE_CISCO_SSH_OPTIONS     | sshOptions (parsed as JSON) | {"KexAlgorithms":"+diffie-hellman-group-exchange-sha1","HostKeyAlgorithms":"+ssh-rsa"}|
| PROFILE_CISCO_JUMP_COMMAND    | jumpCommand                 | telnet lh |
| PROFILE_CISCO_PRESET          | preset                      | topex |
| PROFILE_CISCO_PORT            | port                        | 2222 |
| PROFILE_CISCO_WHITELIST       | per-profile command whitelist (comma-separated or JSON array) | show ospf neigh,show version |
| PROFILE_CISCO_BLACKLIST       | per-profile command blacklist (comma-separated or JSON array) | show running config,conf t |
| PROFILE_CISCO_DISABLE_PAGER   | per-profile pager toggle (`true`/`false`) | false |


`ssh_connect host=10.0.0.1 profile=CISCO connectionId=SWITCH1"`

#### Per-Profile Command Filtering

In addition to the global `SSH_WHITELIST` / `SSH_BLACKLIST`, each profile can carry its own command filter via `PROFILE_<NAME>_WHITELIST` and `PROFILE_<NAME>_BLACKLIST`. These are layered on top of the global filter at execution time for any connection opened with that profile:

* **Profile blacklist always blocks** — even commands the global filter would allow (e.g. block `show running config`).
* **Profile whitelist re-allows** specific commands and, when present, becomes authoritative: anything not listed is blocked (e.g. allow `show ospf neigh` while the blacklist still blocks the rest).
* On direct conflict, the **blacklist wins**.

```bash
export PROFILE_ROUTERS_BLACKLIST="show running config,conf t,configure terminal"
export PROFILE_ROUTERS_WHITELIST="show ospf neigh,show version,show ip interface brief"
```

```
ssh_connect host=10.0.0.1 profile=ROUTERS connectionId=router1
# show ospf neigh        → allowed (profile whitelist)
# show running config    → blocked (profile blacklist)
```

`PROFILE_<NAME>_DISABLE_PAGER=false` turns off pager suppression for connections using that profile, overriding the global `SSH_DISABLE_PAGER` default.


**Usage:**

```
Load connections from /path/to/connections.csv and connect to all
```

> **Note:** You can still provide passwords directly in CSV/JSON if preferred — env var resolution only kicks in when the password field is missing or empty.

### 3. Network Device Types

The server supports different device types with appropriate connection handling:

| Device Type | Behavior | Use Case |
|-------------|----------|----------|
| `linux` | Standard SSH exec mode (default) | Linux/Unix servers |
| `cisco` | Persistent shell, enable mode support | Cisco IOS/IOS-XE routers and switches |
| `cisco_xe` | Persistent shell (`terminal length 0`) | Cisco IOS-XE |
| `cisco_xr` | Persistent shell (`terminal length 0`) | Cisco IOS-XR |
| `cisco_asa` | Persistent shell (`terminal length 0`) | Cisco ASA firewalls |
| `cisco_nexus` | Persistent shell (`terminal length 0`) | Cisco Nexus (NX-OS) |
| `juniper` | Persistent shell (`set cli screen-length 0`) | Juniper JunOS devices |
| `mikrotik` | Persistent shell | MikroTik RouterOS |
| `fortinet` | Persistent shell (`config system console` / `set output standard`) | FortiGate / FortiOS firewalls |
| `paloalto` | Persistent shell (`set cli pager off`) | Palo Alto PAN-OS firewalls |
| `sophos` | Persistent shell (pager auto-handled at runtime) | Sophos XG/XGS (SFOS) firewalls |
| `network` | Generic persistent shell | Other network devices |
| `jump_shell` | Persistent shell + nested CLI | Used internally by `ssh_connect_with_jump_command` |

Network devices use PTY-allocated persistent shell sessions instead of standard `exec()` because many network operating systems close the SSH channel after each exec command.

### 4. One-Shot Command (`ssh_run`)

`ssh_connect` + `ssh_execute` + `ssh_disconnect` is three tool calls, and the middle two require the model to copy a generated connectionId verbatim. `ssh_run` collapses that into one call:

```json
{
  "host": "10.1.2.15",
  "profile": "ROUTERS",
  "command": "show version"
}
```

Connects, runs the command, and closes the connection. Returns the command output — no connectionId to track.

**On failure the connection is kept open** so you can retry a different command. The result is a structured object (returned both as JSON text and in `structuredContent`):

```json
{
  "status": "error",
  "connectionId": "10_1_2_15_2026_08_12_sessionid_a1b2c3",
  "command": "show bogus",
  "error": "Command exited with code 2",
  "exitCode": 2,
  "output": "% Invalid input detected",
  "retry": "The SSH connection is still open. Call ssh_execute with this connectionId to run a different command, then ssh_disconnect when finished."
}
```

Retry with `ssh_execute` using that `connectionId`, then `ssh_disconnect`. Abandoned connections are reaped by `SSH_IDLE_TIMEOUT` (default 120s).

Profiles, whitelist/blacklist, host filter, audit logging, pager handling, and large-output offload all behave exactly as with `ssh_connect` + `ssh_execute`. A command blocked by the filter is rejected **before** any SSH session is opened.

Success is defined as: the command executed and its exit code is `0` or absent. Network devices on the persistent-shell path do not report exit codes, so those commands are successful unless execution itself fails. On Linux a non-zero exit code counts as a failure and keeps the connection open.

#### Nested CLI with fallbacks (`ssh_run_with_jump`)

Same one-call flow, but enters a nested CLI first. `jumpCommands` is a list tried in order until one reaches the nested prompt:

```json
{
  "host": "10.0.0.1",
  "username": "admin",
  "preset": "topex",
  "jumpCommands": ["telnet lh", "telnet 127.0.0.1"],
  "command": "view portsoncard *"
}
```

If `telnet lh` fails to reach the prompt, `telnet 127.0.0.1` is tried. Each attempt is a fresh connection, so a half-open telnet from a failed attempt cannot corrupt the next one. If every candidate fails, the error lists what each one returned.

All candidates share one `jumpPromptPattern` (supplied directly or via `preset`). When candidates need *different* prompt patterns, use `ssh_connect_with_jump_command` instead. `PROFILE_<NAME>_JUMP_COMMAND` supplies a single candidate when `jumpCommands` is omitted.

### 5. Execute on Multiple Connections

Run a command on specific connections using `ssh_execute_on_multiple`:

```json
{
  "command": "show version",
  "connectionIds": ["router1", "router2", "switch1"]
}
```

Or run on ALL connections:

```json
{
  "command": "show ip interface brief",
  "connectionIds": ["*"]
}
```

### 6. Jump Shell (Nested CLI via SSH)

Use `ssh_connect_with_jump_command` when you need to SSH into a host and then enter a nested interactive shell before executing commands. This covers scenarios like:

* **Telnet to a Topex VoIP gateway** from an SSH jump host
* **FreeSWITCH `fs_cli`** on a remote server
* Any CLI that requires an interactive session after SSH

**How it works:**

```
SSH → open shell → send jump command (e.g. "telnet lh") → wait for nested prompt (e.g. "topexsw>") → ready
```

All subsequent `ssh_execute` commands on that connectionId run inside the nested shell.

**Topex gateway example (with preset):**

```json
{
  "host": "10.0.0.1",
  "username": "admin",
  "connectionId": "topex1",
  "preset": "topex",
  "jumpCommand": "telnet lh"
}
```

The `topex` preset auto-fills `jumpPromptPattern: "topexsw>\\s*$"` and `jumpExitCommand: "quit"`. You only need to supply `jumpCommand`.

Then execute commands inside the Topex CLI:

```json
{
  "command": "view portsoncard *",
  "connectionId": "topex1"
}
```

**FreeSWITCH example (preset fills everything):**

```json
{
  "host": "10.0.0.5",
  "username": "root",
  "connectionId": "fs1",
  "preset": "freeswitch"
}
```

The `freeswitch` preset auto-fills `jumpCommand: "fs_cli"`, `jumpPromptPattern: "freeswitch@...>"`, and `jumpExitCommand: "/exit"`. Then:

```json
{
  "command": "sofia status",
  "connectionId": "fs1"
}
```

**Fully custom (no preset):**

```json
{
  "host": "10.0.0.1",
  "username": "admin",
  "connectionId": "custom1",
  "jumpCommand": "telnet 192.168.1.100",
  "jumpPromptPattern": ">\\s*$",
  "jumpExitCommand": "quit",
  "jumpReadyTimeout": 8000
}
```

**Built-in presets:**

| Preset | jumpCommand | Prompt pattern | Exit command |
|--------|-------------|----------------|--------------|
| `freeswitch` | `fs_cli` | `freeswitch@...>` | `/exit` |
| `topex` | *(user provides)* | `topexsw>` | `quit` |

Presets can be overridden — any explicitly provided parameter takes precedence.

**Shell recovery:** If the shell drops, `ssh_execute` automatically reopens the shell and re-enters the jump shell.

**Disconnect:** `ssh_disconnect` gracefully sends the exit command to the nested CLI before closing the SSH connection.

### 7. Logging

Set log level via environment variable:

| Variable | Values | Default |
|----------|--------|---------|
| `SSH_LOG_LEVEL` | DEBUG, INFO, WARN, ERROR | INFO |
| `SSH_LOG_FILE` | Path to log file | (none) |

Log format:

```
[2026-01-22T20:26:02.044Z] [INFO ] ✓ SSH connection established to 172.168.0.2:22
[2026-01-22T20:26:02.046Z] [DEBUG] ♥ Keepalive #1 sent to 172.168.0.2 | {"uptime":"10s"}
[2026-01-22T20:26:12.047Z] [WARN ] ⚠ CONNECTION CLOSED BY REMOTE HOST: router1
```

## Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SSH_FILTER_MODE` | `whitelist`, `blacklist`, `disabled` | `blacklist` | Command filtering mode |
| `SSH_ALLOW_SUDO` | `true`, `false` | `true` | Allow sudo commands |
| `SSH_LOG_BLOCKED` | `true`, `false` | `true` | Log blocked commands to stderr |
| `SSH_MCP_CONFIG` | file path | - | Path to config JSON file |
| `SSH_WHITELIST` | comma-separated or JSON | - | Override whitelist commands |
| `SSH_BLACKLIST` | comma-separated or JSON | - | Override blacklist commands |
| `SSH_DANGEROUS_PATTERNS` | JSON array | - | Override dangerous regex patterns |
| `SSH_LOG_LEVEL` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` | Log verbosity |
| `SSH_LOG_FILE` | path | - | Log to file |
| `SSH_HOST_FILTER_MODE`| whitelist, blacklist, disabled | disabled | Host filtering mode |
| `SSH_HOST_WHITELIST` | comma-separated IPs | - | Whitelist of allowed host IPs |
| `SSH_HOST_BLACKLIST` | comma-separated IPs | - | Blacklist of allowed host IPs |
| `SSH_IDLE_TIMEOUT` | seconds | 120 | Idle connection timeout |
|`SSH_FAILED_CONNECTIONS_LOG`|file  path |  ./ssh-failed-connections.json |/var/log/ssh-failed.jsonl |
| `SSH_AUDIT_ENABLED` | `true`, `false` | `true` | Write a per-command session audit (command + full output) to JSONL |
| `SSH_AUDIT_DIR` | path | `./audit` | Directory for daily `audit_YYYY-MM-DD.jsonl` files |
| `SSH_ENABLE_LARGE_OUTPUT` | `true`, `false` | `false` | Offload oversized command output to an upload endpoint and return a URI instead of inline text |
| `SSH_MAX_OUTPUT_LENGTH` | integer (chars) | `10000` | Output size threshold above which output is offloaded |
| `SSH_FILE_UPLOAD_ENDPOINT` | URL | - | POST target for large output. Receives `{content, filename}`, must return `{file_id, artifact_uri}` |
| `SSH_DISABLE_PAGER` | `true`, `false` | `true` | Suppress interactive pagers (`less`/`---(more)---`) on shell and exec |
| `SSH_DISABLE_PAGER_CMD_<DEVICETYPE>` | string | per-device default | Override the disable-pager command for a device type (e.g. `SSH_DISABLE_PAGER_CMD_CISCO`) |
| `SSH_PAGER_REGEX` | regex string | built-in | Override the pattern used to detect a pager prompt |
| `SSH_PAGER_ADVANCE_KEY` | string | `" "` (space) | Key sent to advance to the next pager page |
| `SSH_MAX_PAGER_PAGES` | integer | 1000 | Safety cap on auto-paged pages per command |


Any additional environment variables following the `<CONNECTIONID>_PASSWORD` convention are automatically used for credential resolution (see [Credential Resolution Convention](#credential-resolution-convention)).

### MCP Configuration Examples


### Host whitelist/blacklist:


**Blacklist mode with custom blocked commands:**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_BLOCKED": "true",
      "SSH_BLACKLIST": "rm,rmdir,mkfs,fdisk,shutdown,reboot,halt,poweroff,passwd,useradd,userdel,iptables,crontab,conf t,configure terminal"
    }
  }
}
```

**Whitelist mode (strict — only allow specific commands):**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "whitelist",
      "SSH_ALLOW_SUDO": "false",
      "SSH_LOG_BLOCKED": "true",
      "SSH_WHITELIST": "ls,cat,grep,tail,head,df,du,free,uptime,ps,systemctl,journalctl,docker,kubectl,ping,curl,dig,ss,netstat,show,display"
    }
  }
}
```

**Network operations with credential env vars:**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_LEVEL": "DEBUG",
      "SSH_BLACKLIST": "conf t,configure terminal,rm,shutdown,reboot",
      "ROUTER1_PASSWORD": "admin123",
      "ROUTER1_ENABLE_PASSWORD": "enable123",
      "ROUTER2_PASSWORD": "pass123",
      "SERVER1_PASSWORD": "pass1234"
    }
  }
}
```

Now in chat you simply say `connect to 172.168.0.2 as admin connectionId=router1` — no passwords exposed.

**Via npx (no global install):**

```json
{
  "ssh_mcp": {
    "command": "npx",
    "args": ["@marian-craciunescu/ssh-mcp-server-secured"],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true"
    }
  }
}
```

### Config File

Create `config.json` or `ssh-mcp-config.json`:

```json
{
  "commandFilter": {
    "mode": "whitelist",
    "allowSudo": false,
    "logBlocked": true,
    "whitelist": [
      "ls", "cat", "grep", "df", "ps", "systemctl", "docker", "show", "ping"
    ],
    "blacklist": [
      "rm", "shutdown", "reboot", "passwd", "conf t", "configure terminal"
    ],
    "dangerousPatterns": [
      ";\\s*rm\\s+-rf",
      "curl.*\\|\\s*bash"
    ]
  }
}
```

## Filter Modes

### Blacklist Mode (Default)

Commands in the blacklist are blocked. Everything else is allowed. Supports multi-word entries like `configure terminal` and `conf t`.

```
✓ ls -la
✓ docker ps
✓ show ip interface brief
✗ rm -rf /tmp/files       → Blocked: 'rm' is in blacklist
✗ configure terminal      → Blocked: 'configure terminal' is in blacklist
✗ shutdown now            → Blocked: 'shutdown' is in blacklist
```

### Whitelist Mode

Only commands in the whitelist are allowed. Everything else is blocked.

```
✓ ls -la                  → Allowed: 'ls' is whitelisted
✓ show version            → Allowed: 'show' is whitelisted
✗ vim /etc/hosts          → Blocked: 'vim' not in whitelist
✗ make install            → Blocked: 'make' not in whitelist
```

### Mixed Mode

Both lists are active at once and the filter is **deny-by-default**: a command must match a whitelist entry to run. On a conflict, **the longest matching entry wins**, whichever list it came from. This is what lets you allow a broad prefix, carve a dangerous subset out of it, and then allow a narrower exception back in.

Matching is by prefix: an entry matches when the command equals it, or starts with it followed by a space, tab, or newline. Comparison is lowercased and trimmed.

```
SSH_FILTER_MODE=mixed
SSH_WHITELIST=show, show running-config interface, show running-config | include, ping -c , ls -lha, terminal length 0
SSH_BLACKLIST=show running-config, conf t, configure terminal, reload, rm, shutdown, ping
```

Resulting decisions:

```
✓ show version                            → 'show' (4) beats nothing
✓ show interfaces terse                   → 'show' (4) beats nothing
✗ show running-config                     → 'show running-config' (19) beats 'show' (4)
✓ show running-config interface Gi0/1     → 'show running-config interface' (29) beats 'show running-config' (19)
✓ show running-config | include hostname  → 'show running-config | include' (29) beats 'show running-config' (19)
✓ ping -c 4 8.8.8.8                       → 'ping -c' (7) beats 'ping' (4)
✗ ping 8.8.8.8                            → only 'ping' (4) matches, and it is blacklisted
✓ terminal length 0                       → whitelisted, so the server can disable its own pager
✓ ls -lha                                 → exact whitelist entry
✗ ls -la                                  → matches NEITHER list → blocked by deny-by-default
✗ reload                                  → blacklisted, no whitelist match
✗ rm -rf /tmp/x                           → 'rm' (2) blacklisted, no whitelist match
```

Two things to know:

* **`ls -lha` is allowed but `ls -la` is not.** Whitelist entries are literal prefixes, not patterns. In mixed mode anything you have not explicitly allowed is blocked, so list the exact command forms you intend to run.
* **Exact ties go to the whitelist.** If the same string is in both lists, the command is allowed.

Include your pager-disable commands (`terminal length 0`, `set cli screen-length 0`) in the whitelist. The server issues them itself when opening a shell, and mixed mode would otherwise block them.

Unlike blacklist and whitelist mode, mixed mode does **not** inspect the individual segments of a pipe or chain — it only matches the full command string. Segment-level protection in mixed mode comes from the dangerous-pattern list, which runs first and cannot be overridden:

```
✗ show version | rm -rf /   → Blocked: dangerous pattern /\|\s*rm/i
```

### Disabled Mode

No command filtering (use with caution).

### Command Validation Order

1. Check if filtering disabled
2. Check sudo permission
3. Check dangerous patterns (regex) — always wins, no whitelist can override
4. In `mixed` mode: longest-match between whitelist and blacklist over the full command; deny-by-default if neither matches. Stops here.
5. Check full command against blacklist (multi-word support)
6. Extract base commands from pipes/chains
7. Check each base command against blacklist/whitelist
8. Apply per-profile (per-connection) whitelist/blacklist on top of the global result

Use `ssh_get_command_filter` to see the active rules and to ask why a specific command would be allowed or blocked.

## Stable Connection IDs

If you don't pass a `connectionId` to `ssh_connect` (or pass `default`), the server generates a stable, structured id and **returns it in the connect response**:

```
<IP>_YYYY_MM_DD_sessionid_<6 random chars>
```

Example: `10_0_0_1_2026_06_08_sessionid_a1b9f3`

The IP dots are replaced with `_` so the id is safe to use as an env-var prefix (for `<PREFIX>_PASSWORD` resolution) and as a filename. Capture the returned `connectionId` and reuse it for subsequent `ssh_execute` / `ssh_disconnect` calls.

## Session Audit (command + output)

Every executed command and its output is written as a single JSONL line to a per-day file, separate from server diagnostics (`SSH_LOG_FILE`):

```
<SSH_AUDIT_DIR>/audit_YYYY-MM-DD.jsonl
```

Each record:

```json
{"timestamp":"2026-06-08T11:07:12.569Z","connectionId":"10_0_0_1_2026_06_08_sessionid_a1b9f3","host":"10.0.0.1","command":"show version","exitCode":0,"output":"..."}
```

Disable with `SSH_AUDIT_ENABLED=false`.

## Large Output Offloading

When a command's output exceeds `SSH_MAX_OUTPUT_LENGTH` and `SSH_ENABLE_LARGE_OUTPUT=true`, the full output is POSTed to `SSH_FILE_UPLOAD_ENDPOINT` and the caller receives a short stub containing the returned `artifact_uri` and `file_id` plus a small preview — so a huge `show tech-support` never floods the model context. The endpoint receives `{ "content": "...", "filename": "..." }` and must return `{ "file_id": "...", "artifact_uri": "..." }`. If the endpoint is unset or the upload fails, output is returned inline as a fallback.

## Pager Handling

Interactive pagers (Linux `less`, Cisco/Juniper `---(more)---`) otherwise block a command until it times out. The server handles this two ways:

* **Prevention** — on shell open it sends a device-appropriate disable-pager command (`terminal length 0` for Cisco, `set cli screen-length 0` for Juniper), and on Linux exec it sets `SYSTEMD_PAGER=`, `PAGER=cat`, `GIT_PAGER=cat`.
* **Detection** — if a pager prompt still appears, it auto-advances (sends a space, capped by `SSH_MAX_PAGER_PAGES`) on network shells, or sends `q` to quit an interactive Linux pager, then strips the prompt artifacts from the output.

Toggle globally with `SSH_DISABLE_PAGER=false`, per-profile with `PROFILE_<NAME>_DISABLE_PAGER=false`, override the command per device type with `SSH_DISABLE_PAGER_CMD_<DEVICETYPE>`, and override detection with `SSH_PAGER_REGEX` / `SSH_PAGER_ADVANCE_KEY`.

## Dangerous Patterns

These patterns are **always blocked** regardless of filter mode:

| Pattern | Example | Risk |
|---------|---------|------|
| Fork bomb | `:(){ :\|:& };:` | System crash |
| Piped rm | `find . \| rm` | Data loss |
| Chained rm | `ls && rm -rf /` | Data loss |
| Device redirect | `> /dev/sda` | Disk corruption |
| System config overwrite | `> /etc/passwd` | System compromise |
| Remote code execution | `curl \| bash` | Arbitrary code execution |
| Recursive chmod 777 | `chmod -R 777 /` | Security compromise |

## Available Tools

### One-shot (recommended)

| Tool | Description |
|------|-------------|
| `ssh_run` | Connect, run one command, and close the connection on success — one call, no connectionId to track. On failure the connection is left open and its `connectionId` is returned so you can retry a different command with `ssh_execute`. Required: `host`, `command`. |
| `ssh_run_with_jump` | Same as `ssh_run`, but enters a nested CLI first. Takes `jumpCommands` as a list and tries them in order until one reaches the nested prompt. Required: `host`, `command`. |

### Connection management

| Tool | Description |
|------|-------------|
| `ssh_connect` | Open a persistent connection and return a `connectionId`. Password auto-resolved from `<CONNECTIONID>_PASSWORD` env var; supports `sshOptions` for legacy algorithm negotiation. |
| `ssh_connect_with_jump_command` | SSH into a host, then enter a nested CLI (telnet, fs_cli, etc.) via a single jump command. Supports presets. Use this when each candidate needs its own prompt pattern. |
| `ssh_load_connections` | Load connections from a CSV/JSON file (credentials resolved from env vars per connectionId). |
| `ssh_disconnect` | Disconnect one connection. |
| `ssh_disconnect_all` | Disconnect all connections. |

### Execution

| Tool | Description |
|------|-------------|
| `ssh_execute` | Run a command on an existing connection. Required: `command`, `connectionId`. |
| `ssh_execute_on_multiple` | Run a command on selected connections (`["*"]` or `[]` = all). Runs sequentially. |

### Status and introspection

| Tool | Description |
|------|-------------|
| `ssh_get_command_filter` | Show the command filter (whitelist/blacklist, global + per-profile, with precedence rules) and the host filter (allowed/blocked hosts) that apply to a connection; optionally check whether a specific command would be allowed. |
| `ssh_list_connections` | List active connections with status. |
| `ssh_check_connections` | Health check all connections (dead socket detection, shell status). |
| `ssh_failed_connections` | List recent failed connection attempts (from the failed-connections JSONL log). |

### File transfer (SFTP)

| Tool | Description |
|------|-------------|
| `ssh_upload_file` | Upload a file via SFTP. |
| `ssh_download_file` | Download a file via SFTP. |
| `ssh_list_files` | List a remote directory via SFTP. |

## Example Workflow

### Single command (one call)

```
→ ssh_run {
    host: "172.168.0.2",
    profile: "ROUTERS",
    command: "show version"
  }
  (connects, runs, closes; returns the output)
```

### Single command inside a nested CLI (one call)

```
→ ssh_run_with_jump {
    host: "10.0.0.1",
    username: "admin",
    preset: "topex",
    jumpCommands: ["telnet lh", "telnet 127.0.0.1"],
    command: "view portsoncard *"
  }
```

### Retry after a failure

```
1. → ssh_run { host: "172.168.0.2", profile: "ROUTERS", command: "show bogus" }
   ← { status: "error", connectionId: "172_168_0_2_..._sessionid_a1b2c3", exitCode: 2, ... }
     (connection left open)

2. → ssh_execute {
       command: "show interfaces terse",
       connectionId: "172_168_0_2_..._sessionid_a1b2c3"
     }

3. → ssh_disconnect { connectionId: "172_168_0_2_..._sessionid_a1b2c3" }
```

### Fleet operations (persistent connections)

```
1. Load connections from CSV (passwords auto-resolved from env vars)
   → ssh_load_connections { filePath: "devices.csv", connectAll: true }
   (ROUTER1_PASSWORD, ROUTER2_PASSWORD resolved automatically)

2. Execute show commands on all devices
   → ssh_execute_on_multiple {
       command: "show ip interface brief",
       connectionIds: ["*"]
     }

3. Execute a command on one specific router
   → ssh_execute {
       command: "show running-config | include hostname",
       connectionId: "router1"
     }

4. Check connection health
   → ssh_check_connections {}

5. Inspect why a command was blocked
   → ssh_get_command_filter {
       connectionId: "router1",
       command: "configure terminal"
     }

6. Disconnect all
   → ssh_disconnect_all {}
```

## Architecture Notes

### Shell Buffer Management
Buffer is cleared before each command. Stability detection uses buffer unchanged for 3 × 500ms = command complete. Password prompts are detected in the last 200 chars of the buffer.

### Keepalive System
SSH2 sends keepalives every 10 seconds (`keepaliveInterval: 10000`). After 3 failed keepalives, the connection auto-closes (`keepaliveCountMax: 3`). A custom interval logs keepalive count for debugging.

### Connection Health Monitoring
The server detects dead connections (socket destroyed), tracks shell status for network devices, auto-cleans dead connections, and attempts shell reopen on network devices if the shell has closed.

### Jump Shell
When `ssh_connect_with_jump_command` is called, the server: (1) opens an SSH connection, (2) opens a PTY shell, (3) sends the jump command (e.g. `telnet lh`), (4) polls the shell buffer every 300ms for the expected prompt regex, (5) marks the connection as `jump_shell` with `jumpShellActive: true`. On disconnect, the nested CLI exit command is sent before closing the SSH session. On shell recovery, the jump command is automatically re-sent.

### Environment Variable Credential Resolution
When a connection is created (via `ssh_connect` or `ssh_load_connections`), if the password is not provided, the server automatically looks up `<PREFIX>_PASSWORD` from environment variables, where `<PREFIX>` is the connectionId uppercased with non-alphanumeric characters replaced by `_`. The same convention applies to `_ENABLE_PASSWORD` and `_USERNAME`. Explicitly provided values always take precedence.

## Comparison with Original

| Feature | zibdie/SSH-MCP-Server | This Fork |
|---------|----------------------|-----------|
| Basic SSH/SFTP | ✓ | ✓ |
| Command whitelist | ✗ | ✓ |
| Command blacklist | ✗ | ✓ |
| Multi-word blacklist entries | ✗ | ✓ |
| Dangerous pattern detection | ✗ | ✓ |
| Audit logging | ✗ | ✓ |
| Command validation tool | ✗ | ✓ |
| Config file support | ✗ | ✓ |
| Network device types (Cisco, Juniper, MikroTik) | ✗ | ✓ |
| Cisco enable mode | ✗ | ✓ |
| Jump shell (nested CLI via SSH) | ✗ | ✓ |
| Bulk connections from CSV/JSON | ✗ | ✓ |
| Multi-connection execution | ✗ | ✓ |
| Environment variable credentials | ✗ | ✓ |
| Connection health monitoring | ✗ | ✓ |
| Keepalive tracking | ✗ | ✓ |
| `host`/`hostname` compatibility | ✗ | ✓ |

## Development

```bash
# Clone
git clone https://github.com/marian-craciunescu/ssh-mcp-server-secured.git
cd ssh-mcp-server-secured

# Install dependencies
npm install

# Run in development mode
npm run dev

# Test with MCP Inspector
npx @modelcontextprotocol/inspector node index.js
```

## Security Considerations

* **Default is blacklist mode** — provides protection while remaining flexible
* **Dangerous patterns are always checked** — even in disabled mode
* **Audit logging enabled by default** — track blocked attempts
* **Sudo can be restricted** — set `SSH_ALLOW_SUDO=false` for high-security environments
* **Credential isolation** — passwords are resolved from env vars by connectionId, never typed in chat or visible in tool calls

## License

MIT — see [LICENSE](LICENSE) file

## Credits

* Original: [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) by Nour Zibdie
* Security fork: [marian-craciunescu](https://github.com/marian-craciunescu)

## Support

* [Issues](https://github.com/marian-craciunescu/ssh-mcp-server-secured/issues)
* [Discussions](https://github.com/marian-craciunescu/ssh-mcp-server-secured/discussions)