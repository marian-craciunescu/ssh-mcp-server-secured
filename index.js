#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Client } from 'ssh2';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, basename, dirname } from 'path';
import { fileURLToPath } from 'url';

// Get package.json version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf8'));

// Default command filter configuration
const DEFAULT_COMMAND_FILTER = {
  // Mode: 'whitelist' (only allow listed) or 'blacklist' (block listed) or 'disabled'
  mode: 'blacklist',

  // Whitelist: only these commands/binaries are allowed when mode is 'whitelist'
  whitelist: [
    'ls', 'cat', 'head', 'tail', 'grep', 'awk', 'sed', 'find', 'wc', 'sort', 'uniq',
    'df', 'du', 'free', 'uptime', 'whoami', 'pwd', 'date', 'hostname', 'uname',
    'ps', 'top', 'htop', 'pgrep', 'pidof',
    'systemctl', 'journalctl', 'service',
    'docker', 'docker-compose', 'kubectl', 'helm',
    'ping', 'curl', 'wget', 'dig', 'nslookup', 'host', 'traceroute', 'netstat', 'ss',
    'git', 'npm', 'node', 'python', 'python3', 'pip', 'pip3',
    'echo', 'printf', 'test', 'true', 'false', 'env', 'printenv',
  ],

  // Blacklist: these commands/patterns are blocked when mode is 'blacklist'
  blacklist: [
    'rm', 'rmdir', 'unlink',
    'mkfs', 'fdisk', 'parted', 'dd',
    'shutdown', 'reboot', 'halt', 'poweroff', 'init',
    'useradd', 'userdel', 'usermod', 'passwd', 'chpasswd', 'groupadd', 'groupdel',
    'visudo', 'sudoedit',
    'iptables', 'ip6tables', 'nft', 'firewall-cmd', 'ufw',
    'crontab',
    'mount', 'umount',
    'insmod', 'rmmod', 'modprobe',
  ],

  // Dangerous patterns (always blocked regardless of mode)
  dangerousPatterns: [
    ':\\(\\)\\s*\\{\\s*:|:&\\s*\\}\\s*;',  // Fork bomb
    ';\\s*rm\\s+-rf',                       // ; rm -rf
    '\\|\\s*rm',                            // | rm
    '&&\\s*rm',                             // && rm
    '\\|\\|\\s*rm',                         // || rm
    '>\\s*/dev/',                           // redirect to /dev/
    '>\\s*/etc/',                           // redirect to /etc/
    '>\\s*/boot/',                          // redirect to /boot/
    '>\\s*/sys/',                           // redirect to /sys/
    '>\\s*/proc/',                          // redirect to /proc/
    'mkfs',                                 // filesystem creation
    'dd\\s+if=.*of=/dev',                   // dd to device
    'chmod\\s+777\\s+/',                    // chmod 777 on root paths
    'chmod\\s+-R\\s+777',                   // recursive chmod 777
    'chown\\s+-R\\s+.*:\\s*/',              // recursive chown on root
    '>\\.bashrc',                           // overwrite bashrc
    '>\\.profile',                          // overwrite profile
    'curl.*\\|\\s*bash',                    // curl | bash
    'wget.*\\|\\s*bash',                    // wget | bash
    'curl.*\\|\\s*sh',                      // curl | sh
    'wget.*\\|\\s*sh',                      // wget | sh
  ],

  // Allow sudo prefix (if false, any sudo command is blocked)
  allowSudo: true,

  // Log blocked commands for audit
  logBlocked: true,
};

class SSHMCPServer {
  constructor() {
    this.server = new Server(
        {
          name: 'ssh-mcp-server-secured',
          version: packageJson.version,
        },
        {
          capabilities: {
            tools: {},
          },
        }
    );

    this.connections = new Map();
    this.commandFilter = this.loadCommandFilter();
    this.setupToolHandlers();
  }

  /**
   * Load command filter configuration from file or environment
   */
  loadCommandFilter() {
    const config = { ...DEFAULT_COMMAND_FILTER };

    // Check for config file
    const configPaths = [
      process.env.SSH_MCP_CONFIG,
      resolve(__dirname, 'config.json'),
      resolve(process.cwd(), 'ssh-mcp-config.json'),
    ].filter(Boolean);

    for (const configPath of configPaths) {
      if (configPath && existsSync(configPath)) {
        try {
          const fileConfig = JSON.parse(readFileSync(configPath, 'utf8'));
          if (fileConfig.commandFilter) {
            Object.assign(config, fileConfig.commandFilter);
            console.error(`Loaded command filter config from: ${configPath}`);
          }
        } catch (error) {
          console.error(`Failed to load config from ${configPath}: ${error.message}`);
        }
        break;
      }
    }

    // Override with environment variables
    if (process.env.SSH_FILTER_MODE) {
      config.mode = process.env.SSH_FILTER_MODE;
    }
    if (process.env.SSH_ALLOW_SUDO !== undefined) {
      config.allowSudo = process.env.SSH_ALLOW_SUDO === 'true';
    }
    if (process.env.SSH_LOG_BLOCKED !== undefined) {
      config.logBlocked = process.env.SSH_LOG_BLOCKED === 'true';
    }

    // Parse whitelist from env (comma-separated or JSON array)
    if (process.env.SSH_WHITELIST) {
      try {
        // Try JSON array first
        if (process.env.SSH_WHITELIST.startsWith('[')) {
          config.whitelist = JSON.parse(process.env.SSH_WHITELIST);
        } else {
          // Comma-separated list
          config.whitelist = process.env.SSH_WHITELIST.split(',').map(s => s.trim()).filter(Boolean);
        }
        console.error(`Loaded whitelist from env: ${config.whitelist.length} commands`);
      } catch (error) {
        console.error(`Failed to parse SSH_WHITELIST: ${error.message}`);
      }
    }

    // Parse blacklist from env (comma-separated or JSON array)
    if (process.env.SSH_BLACKLIST) {
      try {
        if (process.env.SSH_BLACKLIST.startsWith('[')) {
          config.blacklist = JSON.parse(process.env.SSH_BLACKLIST);
        } else {
          config.blacklist = process.env.SSH_BLACKLIST.split(',').map(s => s.trim()).filter(Boolean);
        }
        console.error(`Loaded blacklist from env: ${config.blacklist.length} commands`);
      } catch (error) {
        console.error(`Failed to parse SSH_BLACKLIST: ${error.message}`);
      }
    }

    // Parse dangerous patterns from env (JSON array of regex strings)
    if (process.env.SSH_DANGEROUS_PATTERNS) {
      try {
        config.dangerousPatterns = JSON.parse(process.env.SSH_DANGEROUS_PATTERNS);
        console.error(`Loaded dangerous patterns from env: ${config.dangerousPatterns.length} patterns`);
      } catch (error) {
        console.error(`Failed to parse SSH_DANGEROUS_PATTERNS: ${error.message}`);
      }
    }

    // Convert arrays to Sets for faster lookup
    return {
      mode: config.mode,
      whitelist: new Set(config.whitelist),
      blacklist: new Set(config.blacklist),
      dangerousPatterns: config.dangerousPatterns.map(p => new RegExp(p, 'i')),
      allowSudo: config.allowSudo,
      logBlocked: config.logBlocked,
    };
  }

  /**
   * Extract the base command/binary from a command string
   */
  extractBaseCommand(command) {
    let cmd = command.trim();

    // Handle sudo prefix
    if (cmd.startsWith('sudo ')) {
      cmd = cmd.slice(5).trim();
      // Handle sudo flags like -S, -u, -p, etc.
      while (cmd.startsWith('-')) {
        const flagMatch = cmd.match(/^-(\S+)\s*/);
        if (flagMatch) {
          const flag = flagMatch[1];
          cmd = cmd.slice(flagMatch[0].length);
          // Flags that take an argument: -u, -g, -p, -r, -t, -C, -h
          if (/^[ugprtCh]/.test(flag) && cmd && !cmd.startsWith('-')) {
            // Skip the argument
            cmd = cmd.replace(/^\S+\s*/, '');
          }
        } else {
          break;
        }
      }
    }

    // Handle environment variables prefix (VAR=value cmd)
    while (/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/.test(cmd)) {
      cmd = cmd.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/, '');
    }

    // Handle path prefix (/usr/bin/ls -> ls)
    const firstPart = cmd.split(/\s+/)[0];
    if (!firstPart) return '';

    const baseName = firstPart.split('/').pop();
    return baseName || '';
  }

  /**
   * Extract ALL commands from a complex command string
   */
  extractAllCommands(command) {
    const commands = [];

    // Split by command separators: |, &&, ||, ;, &
    // But be careful with quoted strings
    const parts = command.split(/\s*(?:\|{1,2}|&&?|;)\s*/);

    for (const part of parts) {
      const baseCmd = this.extractBaseCommand(part.trim());
      if (baseCmd) {
        commands.push(baseCmd);
      }
    }

    return commands;
  }

  /**
   * Validate a command against whitelist/blacklist rules
   */
  validateCommand(command) {
    if (this.commandFilter.mode === 'disabled') {
      return { allowed: true, reason: 'Command filtering disabled' };
    }

    const trimmedCmd = command.trim();

    // Check for sudo if not allowed
    if (!this.commandFilter.allowSudo && /^\s*sudo\s+/.test(trimmedCmd)) {
      this.logBlockedCommand(command, 'sudo commands are not permitted');
      return { allowed: false, reason: 'sudo commands are not permitted' };
    }

    // Always check dangerous patterns first (regardless of mode)
    for (const pattern of this.commandFilter.dangerousPatterns) {
      if (pattern.test(trimmedCmd)) {
        const reason = `Command matches dangerous pattern: ${pattern.toString()}`;
        this.logBlockedCommand(command, reason);
        return { allowed: false, reason };
      }
    }

    // Extract all commands from the string
    const allCommands = this.extractAllCommands(trimmedCmd);

    if (this.commandFilter.mode === 'whitelist') {
      for (const cmd of allCommands) {
        if (!this.commandFilter.whitelist.has(cmd)) {
          const reason = `Command '${cmd}' is not in the allowed whitelist`;
          this.logBlockedCommand(command, reason);
          return { allowed: false, reason };
        }
      }
      return { allowed: true, reason: 'All commands are whitelisted' };

    } else if (this.commandFilter.mode === 'blacklist') {
      for (const cmd of allCommands) {
        if (this.commandFilter.blacklist.has(cmd)) {
          const reason = `Command '${cmd}' is blocked by blacklist`;
          this.logBlockedCommand(command, reason);
          return { allowed: false, reason };
        }
      }
      return { allowed: true, reason: 'No commands are blacklisted' };
    }

    return { allowed: true, reason: 'Unknown mode, allowing' };
  }

  /**
   * Log blocked commands for audit purposes
   */
  logBlockedCommand(command, reason) {
    if (this.commandFilter.logBlocked) {
      const timestamp = new Date().toISOString();
      console.error(`[${timestamp}] BLOCKED: "${command}" - ${reason}`);
    }
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'ssh_connect',
          description: 'Connect to an SSH server using password or SSH key authentication. Supports IPv4 and IPv6.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'SSH server hostname or IP address (IPv4 or IPv6)',
              },
              hostname: {
                type: 'string',
                description: 'Alias for host (for compatibility)',
              },
              port: {
                type: 'number',
                description: 'SSH server port',
                default: 22,
              },
              username: {
                type: 'string',
                description: 'Username for SSH authentication',
              },
              password: {
                type: 'string',
                description: 'Password for authentication (if using password auth)',
              },
              privateKey: {
                type: 'string',
                description: 'Path to private SSH key file (if using key auth)',
              },
              passphrase: {
                type: 'string',
                description: 'Passphrase for encrypted private key (optional)',
              },
              connectionId: {
                type: 'string',
                description: 'Unique identifier for this connection',
                default: 'default',
              },
            },
            required: ['username'],
          },
        },
        {
          name: 'ssh_execute',
          description: 'Execute a command on an established SSH connection. Commands are validated against security filters.',
          inputSchema: {
            type: 'object',
            properties: {
              command: {
                type: 'string',
                description: 'Command to execute on the remote server',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              timeout: {
                type: 'number',
                description: 'Command timeout in milliseconds',
                default: 30000,
              },
              pty: {
                type: 'boolean',
                description: 'Allocate a pseudo-terminal (needed for some interactive commands)',
                default: false,
              },
            },
            required: ['command'],
          },
        },
        {
          name: 'ssh_disconnect',
          description: 'Disconnect from an SSH server',
          inputSchema: {
            type: 'object',
            properties: {
              connectionId: {
                type: 'string',
                description: 'Connection ID to disconnect',
                default: 'default',
              },
            },
          },
        },
        {
          name: 'ssh_list_connections',
          description: 'List all active SSH connections',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'ssh_get_filter_config',
          description: 'Get the current command filter configuration',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'ssh_validate_command',
          description: 'Check if a command would be allowed by the security filter without executing it',
          inputSchema: {
            type: 'object',
            properties: {
              command: {
                type: 'string',
                description: 'Command to validate',
              },
            },
            required: ['command'],
          },
        },
        {
          name: 'ssh_execute_script',
          description: 'Execute a multi-line script or code block on an SSH connection. Scripts are validated against security filters.',
          inputSchema: {
            type: 'object',
            properties: {
              script: {
                type: 'string',
                description: 'Script or code block to execute. Can include triple backticks (```bash, ```python, etc.)',
              },
              interpreter: {
                type: 'string',
                description: 'Script interpreter to use (bash, sh, python, python3, node, etc.)',
                default: 'bash',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              timeout: {
                type: 'number',
                description: 'Script timeout in milliseconds',
                default: 60000,
              },
              workingDir: {
                type: 'string',
                description: 'Working directory to execute script in (optional)',
              },
            },
            required: ['script'],
          },
        },
        {
          name: 'ssh_upload_file',
          description: 'Upload a file to the remote server via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              localPath: {
                type: 'string',
                description: 'Local file path to upload',
              },
              remotePath: {
                type: 'string',
                description: 'Remote destination path',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              createDirs: {
                type: 'boolean',
                description: 'Create remote directories if they don\'t exist',
                default: true,
              },
            },
            required: ['localPath', 'remotePath'],
          },
        },
        {
          name: 'ssh_download_file',
          description: 'Download a file from the remote server via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: {
                type: 'string',
                description: 'Remote file path to download',
              },
              localPath: {
                type: 'string',
                description: 'Local destination path',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              createDirs: {
                type: 'boolean',
                description: 'Create local directories if they don\'t exist',
                default: true,
              },
            },
            required: ['remotePath', 'localPath'],
          },
        },
        {
          name: 'ssh_list_files',
          description: 'List files and directories on the remote server',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: {
                type: 'string',
                description: 'Remote directory path to list',
                default: '.',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              detailed: {
                type: 'boolean',
                description: 'Show detailed file information (permissions, size, etc.)',
                default: false,
              },
            },
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'ssh_connect':
            return await this.handleSSHConnect(args);
          case 'ssh_execute':
            return await this.handleSSHExecute(args);
          case 'ssh_disconnect':
            return await this.handleSSHDisconnect(args);
          case 'ssh_list_connections':
            return await this.handleListConnections();
          case 'ssh_get_filter_config':
            return await this.handleGetFilterConfig();
          case 'ssh_validate_command':
            return await this.handleValidateCommand(args);
          case 'ssh_execute_script':
            return await this.handleSSHExecuteScript(args);
          case 'ssh_upload_file':
            return await this.handleSSHUploadFile(args);
          case 'ssh_download_file':
            return await this.handleSSHDownloadFile(args);
          case 'ssh_list_files':
            return await this.handleSSHListFiles(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async handleSSHConnect(args) {
    const {
      host: hostParam,
      hostname,  // Accept both for compatibility
      port = 22,
      username,
      password,
      privateKey,
      passphrase,
      connectionId = 'default',
    } = args;

    // Use host or hostname (host takes precedence)
    const host = hostParam || hostname;

    if (!host) {
      throw new Error('host (or hostname) is required');
    }

    if (this.connections.has(connectionId)) {
      throw new Error(`Connection '${connectionId}' already exists. Disconnect first or use a different ID.`);
    }

    return new Promise((resolve, reject) => {
      const conn = new Client();

      const config = {
        host,
        port,
        username,
      };

      // Handle IPv6 addresses
      if (host.includes(':') && !host.startsWith('[')) {
        config.host = `[${host}]`;
      }

      // Authentication setup
      if (privateKey) {
        try {
          const keyPath = resolve(privateKey);
          const keyData = readFileSync(keyPath);
          config.privateKey = keyData;
          if (passphrase) {
            config.passphrase = passphrase;
          }
        } catch (error) {
          return reject(new Error(`Failed to read private key: ${error.message}`));
        }
      } else if (password) {
        config.password = password;
      } else {
        return reject(new Error('Either password or privateKey must be provided'));
      }

      conn.on('ready', () => {
        this.connections.set(connectionId, { conn, host, port, username });
        resolve({
          content: [
            {
              type: 'text',
              text: `Successfully connected to ${host}:${port} as ${username} (connection: ${connectionId})`,
            },
          ],
        });
      });

      conn.on('error', (error) => {
        reject(new Error(`SSH connection failed: ${error.message}`));
      });

      conn.on('close', () => {
        this.connections.delete(connectionId);
      });

      conn.connect(config);
    });
  }

  async handleSSHExecute(args) {
    const { command, connectionId = 'default', timeout = 30000, pty = false } = args;

    // Validate command before execution
    const validation = this.validateCommand(command);
    if (!validation.allowed) {
      throw new Error(`Command blocked: ${validation.reason}`);
    }

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const { conn } = connection;

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        reject(new Error(`Command timeout after ${timeout}ms`));
      }, timeout);

      const execOptions = {};

      // Request PTY if needed (for sudo -S or interactive commands)
      if (pty || (command.includes('sudo') && command.includes('-S'))) {
        execOptions.pty = {
          rows: 24,
          cols: 80,
          height: 480,
          width: 640,
          term: 'xterm'
        };
      }

      conn.exec(command, execOptions, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          return reject(new Error(`Failed to execute command: ${err.message}`));
        }

        stream
            .on('close', (code, signal) => {
              clearTimeout(timeoutId);
              resolve({
                content: [
                  {
                    type: 'text',
                    text: `Command: ${command}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nError Output:\n${errorOutput}` : ''}`,
                  },
                ],
              });
            })
            .on('data', (data) => {
              output += data.toString();
            })
            .stderr.on('data', (data) => {
          errorOutput += data.toString();
        });
      });
    });
  }

  async handleSSHDisconnect(args) {
    const { connectionId = 'default' } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    connection.conn.end();
    this.connections.delete(connectionId);

    return {
      content: [
        {
          type: 'text',
          text: `Disconnected from connection: ${connectionId}`,
        },
      ],
    };
  }

  async handleListConnections() {
    const connectionList = Array.from(this.connections.entries()).map(([id, info]) => ({
      id,
      host: info.host,
      port: info.port,
      username: info.username,
    }));

    return {
      content: [
        {
          type: 'text',
          text: connectionList.length > 0
              ? `Active connections:\n${connectionList.map(c => `  - ${c.id}: ${c.username}@${c.host}:${c.port}`).join('\n')}`
              : 'No active connections',
        },
      ],
    };
  }

  async handleGetFilterConfig() {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            mode: this.commandFilter.mode,
            allowSudo: this.commandFilter.allowSudo,
            logBlocked: this.commandFilter.logBlocked,
            whitelistCount: this.commandFilter.whitelist.size,
            blacklistCount: this.commandFilter.blacklist.size,
            dangerousPatternsCount: this.commandFilter.dangerousPatterns.length,
            whitelist: Array.from(this.commandFilter.whitelist),
            blacklist: Array.from(this.commandFilter.blacklist),
          }, null, 2),
        },
      ],
    };
  }

  async handleValidateCommand(args) {
    const { command } = args;
    const validation = this.validateCommand(command);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            command,
            allowed: validation.allowed,
            reason: validation.reason,
            extractedCommands: this.extractAllCommands(command),
          }, null, 2),
        },
      ],
    };
  }

  extractCodeFromBlock(script) {
    const codeBlockRegex = /^```[\w]*\n?([\s\S]*?)\n?```$/;
    const match = script.trim().match(codeBlockRegex);
    return match ? match[1].trim() : script.trim();
  }

  async handleSSHExecuteScript(args) {
    const {
      script,
      interpreter = 'bash',
      connectionId = 'default',
      timeout = 60000,
      workingDir
    } = args;

    // Validate interpreter
    const interpreterValidation = this.validateCommand(interpreter);
    if (!interpreterValidation.allowed) {
      throw new Error(`Interpreter blocked: ${interpreterValidation.reason}`);
    }

    // Validate script content for dangerous patterns
    for (const pattern of this.commandFilter.dangerousPatterns) {
      if (pattern.test(script)) {
        throw new Error(`Script contains dangerous pattern: ${pattern.toString()}`);
      }
    }

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const { conn } = connection;
    const cleanScript = this.extractCodeFromBlock(script);

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        reject(new Error(`Script timeout after ${timeout}ms`));
      }, timeout);

      const scriptName = `mcp_temp_${Date.now()}.${interpreter === 'python' || interpreter === 'python3' ? 'py' : 'sh'}`;
      const remotePath = `/tmp/${scriptName}`;

      let scriptContent = cleanScript;
      if (!scriptContent.startsWith('#!')) {
        const shebang = interpreter === 'python' || interpreter === 'python3'
            ? '#!/usr/bin/env python3'
            : '#!/bin/bash';
        scriptContent = `${shebang}\n${scriptContent}`;
      }

      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timeoutId);
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const writeStream = sftp.createWriteStream(remotePath);
        writeStream.write(scriptContent);
        writeStream.end();

        writeStream.on('close', () => {
          const cdCommand = workingDir ? `cd "${workingDir}" && ` : '';
          const command = `${cdCommand}chmod +x ${remotePath} && ${remotePath} && rm -f ${remotePath}`;

          conn.exec(command, (err, stream) => {
            if (err) {
              clearTimeout(timeoutId);
              return reject(new Error(`Failed to execute script: ${err.message}`));
            }

            stream
                .on('close', (code, signal) => {
                  clearTimeout(timeoutId);
                  resolve({
                    content: [
                      {
                        type: 'text',
                        text: `Script executed with ${interpreter}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nError Output:\n${errorOutput}` : ''}`,
                      },
                    ],
                  });
                })
                .on('data', (data) => {
                  output += data.toString();
                })
                .stderr.on('data', (data) => {
              errorOutput += data.toString();
            });
          });
        });

        writeStream.on('error', (err) => {
          clearTimeout(timeoutId);
          reject(new Error(`Failed to upload script: ${err.message}`));
        });
      });
    });
  }

  async handleSSHUploadFile(args) {
    const { localPath, remotePath, connectionId = 'default', createDirs = true } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const { conn } = connection;
    const absoluteLocalPath = resolve(localPath);

    return new Promise((resolve, reject) => {
      try {
        const fileContent = readFileSync(absoluteLocalPath);

        conn.sftp((err, sftp) => {
          if (err) {
            return reject(new Error(`SFTP error: ${err.message}`));
          }

          const uploadFile = () => {
            const writeStream = sftp.createWriteStream(remotePath);
            writeStream.write(fileContent);
            writeStream.end();

            writeStream.on('close', () => {
              resolve({
                content: [
                  {
                    type: 'text',
                    text: `Successfully uploaded ${absoluteLocalPath} to ${remotePath}`,
                  },
                ],
              });
            });

            writeStream.on('error', (err) => {
              reject(new Error(`Upload failed: ${err.message}`));
            });
          };

          if (createDirs) {
            const remoteDir = dirname(remotePath);
            if (remoteDir !== '.' && remoteDir !== '/') {
              sftp.mkdir(remoteDir, { recursive: true }, () => {
                uploadFile();
              });
            } else {
              uploadFile();
            }
          } else {
            uploadFile();
          }
        });
      } catch (error) {
        reject(new Error(`Failed to read local file: ${error.message}`));
      }
    });
  }

  async handleSSHDownloadFile(args) {
    const { remotePath, localPath, connectionId = 'default', createDirs = true } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const { conn } = connection;
    const absoluteLocalPath = resolve(localPath);

    return new Promise((resolve, reject) => {
      conn.sftp((err, sftp) => {
        if (err) {
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const downloadFile = () => {
          const readStream = sftp.createReadStream(remotePath);
          let fileContent = Buffer.alloc(0);

          readStream.on('data', (chunk) => {
            fileContent = Buffer.concat([fileContent, chunk]);
          });

          readStream.on('end', () => {
            try {
              writeFileSync(absoluteLocalPath, fileContent);
              resolve({
                content: [
                  {
                    type: 'text',
                    text: `Successfully downloaded ${remotePath} to ${absoluteLocalPath}`,
                  },
                ],
              });
            } catch (error) {
              reject(new Error(`Failed to write local file: ${error.message}`));
            }
          });

          readStream.on('error', (err) => {
            reject(new Error(`Download failed: ${err.message}`));
          });
        };

        if (createDirs) {
          const localDir = dirname(absoluteLocalPath);
          try {
            mkdirSync(localDir, { recursive: true });
          } catch (error) {
            // Ignore mkdir errors if directory already exists
          }
        }

        downloadFile();
      });
    });
  }

  async handleSSHListFiles(args) {
    const { remotePath = '.', connectionId = 'default', detailed = false } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const { conn } = connection;

    try {
      const sftp = await new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) {
            return reject(new Error(`SFTP error: ${err.message}`));
          }
          resolve(sftp);
        });
      });

      const list = await new Promise((resolve, reject) => {
        sftp.readdir(remotePath, (err, list) => {
          if (err) {
            return reject(new Error(`Failed to list directory: ${err.message}`));
          }
          resolve(list);
        });
      });

      let output = `Directory listing for: ${remotePath}\n\n`;

      if (detailed) {
        output += 'Permissions  Size     Modified                Name\n';
        output += '-'.repeat(60) + '\n';

        list.forEach(item => {
          const isDir = item.attrs.isDirectory() ? 'd' : '-';
          const perms = item.attrs.mode ? (item.attrs.mode & parseInt('777', 8)).toString(8).padStart(3, '0') : '???';
          const size = item.attrs.size ? item.attrs.size.toString().padStart(8) : '???';
          const mtime = item.attrs.mtime ? new Date(item.attrs.mtime * 1000).toISOString() : 'Unknown';

          output += `${isDir}${perms}      ${size}   ${mtime}  ${item.filename}\n`;
        });
      } else {
        const dirs = list.filter(item => item.attrs.isDirectory()).map(item => item.filename + '/');
        const files = list.filter(item => !item.attrs.isDirectory()).map(item => item.filename);

        if (dirs.length > 0) {
          output += 'Directories:\n';
          dirs.forEach(dir => output += `  ${dir}\n`);
          output += '\n';
        }

        if (files.length > 0) {
          output += 'Files:\n';
          files.forEach(file => output += `  ${file}\n`);
        }

        if (dirs.length === 0 && files.length === 0) {
          output += 'Directory is empty';
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: output,
          },
        ],
      };
    } catch (error) {
      throw error;
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error(`SSH MCP Server (Secured) v${packageJson.version} running on stdio`);
    console.error(`Command filter mode: ${this.commandFilter.mode}`);
  }
}

const server = new SSHMCPServer();
server.run().catch(console.error);
