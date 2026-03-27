# SSH MCP Server (Secured)

[![npm version](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured.svg)](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured)
[![CI/CD](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml/badge.svg)](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **secured** fork of [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) with command whitelist/blacklist filtering, network device support, and bulk connection management for safe remote server management via MCP (Model Context Protocol).

## Key Features

* **Command Whitelist/Blacklist**: Control which commands can be executed
* **Dangerous Pattern Detection**: Blocks fork bombs, command injection, and destructive patterns
* **Network Device Support**: Cisco, Juniper, MikroTik with persistent shell sessions and enable mode
* **Jump Shell Support**: SSH into a host then enter a nested CLI (telnet to a host, FreeSWITCH fs_cli, etc.) — commands execute inside the nested shell
* **Bulk Connection Management**: Load dozens of connections from CSV/JSON files
* **Environment Variable Credentials**: Passwords auto-resolved from env vars by connectionId — no secrets in chat
* **Multi-Connection Execution**: Run commands across all or selected connections simultaneously
* **Connection Health Monitoring**: Keepalive tracking, dead connection detection, auto-cleanup
* **Configurable Security Policies**: Via config file or environment variables
* **Audit Logging**: Log all blocked command attempts

## Original zibdie/ssh-mcp-server-secured Features

- **Cross-platform compatibility**: Works on Windows, macOS, and Linux
- **Multiple authentication methods**: Username/password and SSH key and agent authentication 
- **IPv4 and IPv6 support**: Connect to servers using either IP version
- **Multiple connections**: Manage multiple SSH connections simultaneously
- **Comprehensive file operations**: Upload, download, and list files via SFTP
- **Script execution**: Run bash, python, and other scripts remotely
- **Secure**: Uses the robust `ssh2` library for secure connections
- **MCP compatible**: Works with Claude CLI, Claude Desktop, and other MCP clients

## Installation & Setup

### Quick Setup (Recommended)

1. **Add to Claude CLI with one command (cross-platform):**

   ```bash
   npx @marian-craciunescu/ssh-mcp-server-secured@latest --install
   ```

   This auto-detects your OS and registers the MCP server with the correct configuration for your platform.

   **Or manually, if you prefer:**

   **macOS/Linux:**
   ```bash
   claude mcp add ssh-mcp-secured npx '@marian-craciunescu/ssh-mcp-server-secured@latest'
   ```

   **Windows:**
   ```bash
   claude mcp add ssh-mcp-secured -- cmd /c npx @marian-craciunescu/ssh-mcp-server-secured@latest
   ```

   > **Why the difference?** On Windows, `npx` is a batch file (`npx.cmd`). Claude Code launches MCP servers using Node.js `child_process.spawn()`, which cannot execute `.cmd` files directly. The `cmd /c` wrapper tells Windows to run it through the command interpreter.

2. **Restart Claude CLI**

3. **Test the connection:**
   ```
   "Connect to my server at example.com with username myuser"
   ```

### Alternative: Manual Installation

#### For Claude CLI

1. **Install globally:**

   ```bash
   npm install -g @marian-craciunescu/ssh-mcp-server-secured
   ```

2. **Add to configuration:**

   **macOS/Linux**: Edit `~/.config/claude/claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "ssh-mcp-secured": {
         "command": "ssh-mcp-server-secured"
       }
     }
   }
   ```

   **Windows**: Edit `%APPDATA%\Claude\claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "ssh-mcp-secured": {
         "command": "cmd",
         "args": ["/c", "ssh-mcp-server-secured"]
       }
     }
   }
   ```

#### For Claude Desktop

1. **Install globally:**

   ```bash
   npm install -g @marian-craciunescu/ssh-mcp-server-secured
   ```

2. **Add to configuration:**

   **macOS**: Edit `~/Library/Application Support/Claude/claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "ssh-mcp-secured": {
         "command": "ssh-mcp-server-secured"
       }
     }
   }
   ```

   **Windows**: Edit `%APPDATA%\Claude\claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "ssh-mcp-secured": {
         "command": "cmd",
         "args": ["/c", "ssh-mcp-server-secured"]
       }
     }
   }
   ```

## Demo

Here's an example of the SSH MCP server in action, showing file upload capabilities:

![SSH MCP Server Demo](demo_photo.png)

_Example: Uploading and managing files on remote servers through Claude using the SSH MCP server_

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


`ssh_connect host=10.0.0.1 profile=CISCO connectionId=SWITCH1"`

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
| `juniper` | Persistent shell | Juniper JunOS devices |
| `mikrotik` | Persistent shell | MikroTik RouterOS |
| `network` | Generic persistent shell | Other network devices |
| `jump_shell` | Persistent shell + nested CLI | Used internally by `ssh_connect_with_jump_command` |

Network devices use PTY-allocated persistent shell sessions instead of standard `exec()` because many network operating systems close the SSH channel after each exec command.

### 4. Cisco Enable Mode

Enter privileged EXEC mode on Cisco devices using `ssh_cisco_enable`:

```json
{
  "connectionId": "router1"
}
```

The tool handles the interactive enable password prompt automatically — it sends `enable`, waits for `Password:`, sends the stored `enablePassword`, and verifies the prompt changed to `#`.

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
| `SSH_FAILED_CONNECTIONS_LOG`|file  path |  ./ssh-failed-connections.json |/var/log/ssh-failed.jsonl |
| `SSH_ALLOW_PRIVATE_KEY_ACCESS` | `true`, `false` | `false` | When `true`, disables the SFTP restriction that prevents uploading/downloading the private key file used by a connection |


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

### Disabled Mode

No command filtering (use with caution).

### Command Validation Order

1. Check if filtering disabled
2. Check sudo permission
3. Check dangerous patterns (regex)
4. Check full command against blacklist (multi-word support)
5. Extract base commands from pipes/chains
6. Check each base command against blacklist/whitelist

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

| Tool | Description | Parameters |
|------|-------------|------------|
| `ssh_connect` | Connect to an SSH server using password or SSH key authentication. | - `host` (required): SSH server hostname or IP address (IPv4 or IPv6)<br>- `port` (optional): SSH server port (default: 22)<br>- `username` (required): Username for SSH authentication<br>- `password` (optional): Password for authentication<br>- `privateKey` (optional): Path to private SSH key file<br>- `passphrase` (optional): Passphrase for encrypted private key<br>- `connectionId` (optional): Unique identifier for this connection (default: "default") |
| `ssh_execute` | Execute a command on an established SSH connection. | - `command` (required): Command to execute on the remote server<br>- `connectionId` (optional): Connection ID to use (default: "default")<br>- `timeout` (optional): Command timeout in milliseconds (default: 30000) |
| `ssh_disconnect` | Disconnect from an SSH server. | - `connectionId` (optional): Connection ID to disconnect (default: "default") |
| `ssh_list_connections` | List all active SSH connections. | *(None)* |
| `ssh_upload_file` | Upload a file to the remote server via SFTP. | - `localPath` (required): Local file path to upload<br>- `remotePath` (required): Remote destination path<br>- `connectionId` (optional): Connection ID to use (default: "default")<br>- `createDirs` (optional): Create remote directories if they don't exist (default: true) |
| `ssh_download_file` | Download a file from the remote server via SFTP. | - `remotePath` (required): Remote file path to download<br>- `localPath` (required): Local destination path<br>- `connectionId` (optional): Connection ID to use (default: "default")<br>- `createDirs` (optional): Create local directories if they don't exist (default: true) |
| `ssh_list_files` | List files and directories on the remote server. | - `remotePath` (optional): Remote directory path to list (default: ".")<br>- `connectionId` (optional): Connection ID to use (default: "default")<br>- `detailed` (optional): Show detailed file information (default: false) |

## Examples

### Basic Connection Examples

**User prompt:** "Connect to my server at 192.168.1.100 with username admin and password mypass123"

```
ssh_connect with host="192.168.1.100", username="admin", password="mypass123"
```

**User prompt:** "SSH into my development server using my private key"

```
ssh_connect with host="dev.example.com", username="developer", privateKey="~/.ssh/id_rsa"
```

**User prompt:** "Connect to my IPv6 server with SSH key authentication"

```
ssh_connect with host="2001:db8::1", username="user", privateKey="/home/user/.ssh/dev_key", passphrase="keypassword"
```

### Command Execution Examples

**User prompt:** "Check the disk space on my server"

```
ssh_execute with command="df -h"
```

**User prompt:** "Show me what processes are running"

```
ssh_execute with command="ps aux | head -20"
```

**User prompt:** "Run a system update on my Ubuntu server"

```
ssh_execute_script with script="""
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
echo "System update completed"
""", interpreter="bash"
```

### File Transfer Examples

**User prompt:** "Copy the hello.zip file from my server's desktop to my desktop"

```
ssh_download_file with remotePath="/home/user/Desktop/hello.zip", localPath="~/Desktop/hello.zip"
```

**User prompt:** "Upload my config.json file to the server's /etc/myapp/ directory"

```
ssh_upload_file with localPath="./config.json", remotePath="/etc/myapp/config.json"
```

**User prompt:** "Send my backup script to the server and run it"

```
ssh_upload_and_execute with script="""
#!/bin/bash
mkdir -p /backup/$(date +%Y%m%d)
tar -czf /backup/$(date +%Y%m%d)/data_backup.tar.gz /var/www/html
echo "Backup completed successfully"
""", filename="backup.sh", interpreter="bash"
```

**User prompt:** "Show me what's in the /var/log directory with file sizes"

```
ssh_list_files with remotePath="/var/log", detailed=true
```

### Multi-Server Management Examples

**User prompt:** "Connect to both my production and staging servers"

```
ssh_connect with host="prod.example.com", username="admin", privateKey="~/.ssh/prod_key", connectionId="production"
ssh_connect with host="staging.example.com", username="admin", privateKey="~/.ssh/staging_key", connectionId="staging"
```

**User prompt:** "Check uptime on both servers"

```
ssh_execute with command="uptime", connectionId="production"
ssh_execute with command="uptime", connectionId="staging"
```

**User prompt:** "Deploy my app to staging server"

```
ssh_upload_file with localPath="./myapp.tar.gz", remotePath="/tmp/myapp.tar.gz", connectionId="staging"
ssh_execute_script with script="""
cd /var/www
sudo tar -xzf /tmp/myapp.tar.gz
sudo systemctl restart nginx
sudo systemctl restart myapp
echo "Deployment completed"
""", connectionId="staging", interpreter="bash"
```

### Advanced Scripting Examples

**User prompt:** "Run a Python script to analyze server performance"

```
ssh_execute_script with script="""
import psutil
import json

# Get system info
cpu_percent = psutil.cpu_percent(interval=1)
memory = psutil.virtual_memory()
disk = psutil.disk_usage('/')

report = {
    'cpu_usage': cpu_percent,
    'memory_usage': memory.percent,
    'disk_usage': (disk.used / disk.total) * 100,
    'available_memory_gb': memory.available / (1024**3)
}

print(json.dumps(report, indent=2))
""", interpreter="python3"
```

**User prompt:** "Monitor my application logs in real-time"

```
ssh_execute with command="tail -f /var/log/myapp/application.log", timeout=60000
```

**User prompt:** "Backup my database and download it"

```
ssh_execute_script with script="""
timestamp=$(date +%Y%m%d_%H%M%S)
mysqldump -u dbuser -p'dbpass' mydatabase > /tmp/backup_$timestamp.sql
gzip /tmp/backup_$timestamp.sql
echo "Backup created: /tmp/backup_$timestamp.sql.gz"
""", interpreter="bash"

# Then download the backup
ssh_download_file with remotePath="/tmp/backup_20241203_143022.sql.gz", localPath="./database_backup.sql.gz"
```

### Example Workflow

```
1. Load connections from CSV (passwords auto-resolved from env vars)
   → ssh_load_connections { filePath: "devices.csv", connectAll: true }
   (ROUTER1_PASSWORD, ROUTER2_PASSWORD resolved automatically)

2. Enter enable mode on Cisco routers
   → ssh_cisco_enable { connectionId: "router1" }
   → ssh_cisco_enable { connectionId: "router2" }

3. Execute show commands on all devices
   → ssh_execute_on_multiple {
       command: "show ip interface brief",
       connectionIds: ["*"]
     }

4. Execute privileged command on specific router
   → ssh_execute {
       command: "show running-config | include hostname",
       connectionId: "router1"
     }

5. Check connection health
   → ssh_check_connections {}

6. Connect to a Topex gateway via jump shell
   → ssh_connect_with_jump_command {
       host: "10.0.0.1",
       username: "admin",
       connectionId: "topex1",
       preset: "topex",
       jumpCommand: "telnet lh"
     }

7. Execute command inside the Topex CLI
   → ssh_execute {
       command: "view portsoncard *",
       connectionId: "topex1"
     }

8. Disconnect all
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

## Security Considerations

- This tool provides direct SSH access to remote servers
- Always use strong authentication (prefer SSH keys over passwords)
- Be cautious when executing commands with elevated privileges
- Ensure proper network security and access controls
- Private keys and passwords are handled securely in memory
- Never commit credentials to version control
- **Default is blacklist mode** — provides protection while remaining flexible
- **Dangerous patterns are always checked** — even in disabled mode
- **Audit logging enabled by default** — track blocked attempts
- **Sudo can be restricted** — set `SSH_ALLOW_SUDO=false` for high-security environments
- **Credential isolation** — passwords are resolved from env vars by connectionId, never typed in chat or visible in tool calls

## Requirements

- Node.js 18 or higher
- Network access to target SSH servers
- Valid SSH credentials for target servers

## Troubleshooting

### Common Issues

1. **MCP server fails to start on Windows**

   On Windows, `npx` and globally-installed npm commands are `.cmd` batch files. Claude Code uses `child_process.spawn()` to launch MCP servers, which cannot execute `.cmd` files directly. You must wrap the command with `cmd /c`:

   ```bash
   # Quick setup (Windows)
   claude mcp add ssh-mcp-server-secured -- cmd /c npx @marian-craciunescu/ssh-mcp-server-secured@latest

   # Or for global install (Windows)
   claude mcp add ssh-mcp-server-secured -- cmd /c ssh-mcp-server
   ```

   If editing the config JSON manually, use:
   ```json
   {
     "command": "cmd",
     "args": ["/c", "npx", "@marian-craciunescu/ssh-mcp-server-secured@latest"]
   }
   ```

   You can verify your setup by running `/doctor` in Claude CLI.

2. **"Command not found" after global install**

   ```bash
   # Ensure npm global bin is in your PATH
   npm config get prefix
   export PATH="$(npm config get prefix)/bin:$PATH"
   ```

3. **MCP server not appearing in Claude**

   - Verify configuration file path and JSON syntax
   - Restart Claude CLI/Desktop after configuration changes
   - Check Claude logs for connection errors

4. **SSH connection failures**

   - Verify network connectivity to target server
   - Ensure SSH service is running on target server
   - Check firewall settings and port accessibility
   - Validate SSH credentials and key permissions

5. **Permission errors**
   - Ensure SSH keys have correct permissions (600)
   - Verify user has necessary privileges on target server

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

## API Reference

* **Default is blacklist mode** — provides protection while remaining flexible
* **Dangerous patterns are always checked** — even in disabled mode
* **Audit logging enabled by default** — track blocked attempts
* **Sudo can be restricted** — set `SSH_ALLOW_SUDO=false` for high-security environments
* **Credential isolation** — passwords are resolved from env vars by connectionId, never typed in chat or visible in tool calls
* **Private key protection** — SFTP upload/download operations are blocked from accessing the private key file used for the connection. Set `SSH_ALLOW_PRIVATE_KEY_ACCESS=true` to disable this safeguard if you need to transfer key files intentionally

## License

MIT — see [LICENSE](LICENSE) file

## Credits

* Original: [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) by Nour Zibdie
* Security fork: [marian-craciunescu](https://github.com/marian-craciunescu)

## Support

* [Issues](https://github.com/marian-craciunescu/ssh-mcp-server-secured/issues)
* [Discussions](https://github.com/marian-craciunescu/ssh-mcp-server-secured/discussions)
