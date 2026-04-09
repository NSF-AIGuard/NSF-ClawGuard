# NSF-ClawGuard

A real-time security monitoring plugin for [OpenClaw](https://github.com/openclaw), intelligently identifying risks and providing handling solutions.

## Features

- **Configuration Security Scanning** - Static analysis of OpenClaw configuration files for security issues
- **Prompt Injection Detection** - Detects SOUL.md prompt injection attacks
- **Skill Code Security Scanning** - Local static security scanning for skills
  - SSRF detection
  - Prompt injection detection
  - RCE/dangerous call detection
  - Credential theft detection
- **Command Security Monitoring** - Runtime detection of dangerous command patterns (reverse shells, etc.)
- **Web Dashboard** - Real-time security events dashboard
- **Audit Logging** - Gateway authentication logs and tool call tracking
- **Token Usage Monitoring** - Track AI model token consumption
- **Remote Reporting** - Report security violations to remote servers
- **Port Scanning** - Network port scanning capabilities

## Architecture

```
NSF-ClawGuard/
├── src/
│   ├── api.ts                 # Remote API reporting & heartbeat
│   ├── command-security.ts    # Runtime dangerous command detection
│   ├── config-scanner.ts      # Configuration file security scanner
│   ├── database.ts            # SQLite database operations
│   ├── event-store.ts         # Security event storage
│   ├── logger.ts              # Logging utilities
│   ├── request.ts             # HTTP request manager
│   ├── skill-scanner.ts       # Skill code static security scanner
│   ├── constants.ts           # Constants
│   ├── types.ts               # TypeScript type definitions
│   ├── utils.ts               # Utility functions
│   ├── cli/                   # CLI commands
│   ├── scan-port/             # Port scanning module
│   └── server/                # Web UI server
│       ├── audit.ts           # Audit log handlers
│       ├── inspect.ts         # Security event handlers
│       ├── router.ts          # Router setup
│       ├── static.ts          # Static file serving
│       ├── utils.ts           # Server utilities
│       └── ui/                # Web UI (React)
├── tests/                     # Unit tests
├── index.ts                   # Plugin entry point
├── openclaw.plugin.json       # Plugin manifest
└── package.json
```

## Installation

```bash
npm install
```

## Development

```bash
# Build
npm run build

# Run tests
npm test

# Watch mode for tests
npm run test:watch

# Coverage report
npm run test:coverage

# Full build
npm run build:full
```

## Security Scanning Capabilities

### Configuration Scanner

Scans OpenClaw configuration (`~/.openclaw/openclaw.json`) for:
- Token security issues
- Network security misconfigurations
- Plugin security settings
- Rate limiting configurations
- Authentication settings

### Skill Scanner

Static security analysis for skill code:
- **SSRF** - Server-Side Request Forgery via fetch/axios/http with user-controlled URLs
- **Prompt Injection** - User input directly concatenated into LLM prompts
- **RCE** - Dangerous functions like eval/exec/require
- **Credential Theft** - Environment variables, SSH keys, AWS credentials, GitHub tokens

### Command Security Monitor

Runtime detection of dangerous command patterns:
- Reverse shells (bash -i, nc -e, socat, etc.)
- Network socket operations
- File destruction commands
- Script interpreters with dangerous options

## Web Dashboard

Access the dashboard via the registered HTTP route:
- Security Events Overview
- Threat Distribution Charts
- Gateway Authentication Logs
- Token Consumption Statistics
- Tool Call Records

## Configuration

The plugin reads MCP config paths from `openclaw.plugin.json`:

```json
{
  "id": "lm-security",
  "name": "LM Security Plugin",
  "configSchema": {
    "type": "object",
    "properties": {
      "mcpPaths": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Paths to MCP config files to monitor"
      }
    }
  }
}
```

## License

MIT License - See [LICENSE](LICENSE) for details.
