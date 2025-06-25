# Procedure Schema Reference

The complete schema definition is available in [schema.json](../schema.json). 
All procedures use standardized YAML format with the following structure.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique UUID identifier |
| `name` | string | Human-readable procedure name |
| `description` | string | What the procedure accomplishes |
| `tactic` | string | MITRE ATT&CK tactic (discovery, execution, etc.) |
| `technique` | object | MITRE ATT&CK technique information |
| `technique.attack_id` | string | ATT&CK technique ID (T1057, T1021.006) |
| `technique.name` | string | Full ATT&CK technique name |
| `platforms` | object | Platform-specific implementations |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `singleton` | boolean | Runs only once per operation (default: false) |
| `repeatable` | boolean | Can be repeated multiple times (default: false) |
| `delete_payload` | boolean | Delete payload files after execution (default: true) |
| `privilege` | string | Required privilege level: "", "User", "Elevated", "SYSTEM" |
| `buckets` | array | Classification tags |
| `requirements` | array | Prerequisites for execution |
| `access` | object | Access control requirements |
| `plugin` | string | Source plugin name |

## Platform Executors

| Platform | Executor | Description |
|----------|----------|-------------|
| `windows` | `psh` | PowerShell |
| `windows` | `pwsh` | PowerShell Core |
| `windows` | `cmd` | Command Prompt |
| `windows` | `donut_amd64` | Compiled C# executables |
| `linux` | `sh` | Shell script |
| `darwin` | `sh` | Shell script |
| `darwin` | `osa` | AppleScript/OSA |
| `darwin,linux` | `sh` | Shared executor |

## Executor Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `command` | ✅ | string | Command to execute |
| `timeout` | ❌ | integer | Execution timeout in seconds (default: 60) |
| `cleanup` | ❌ | string | Commands to reverse procedure effects |
| `payloads` | ❌ | array | Files required for execution |
| `uploads` | ❌ | array | Files to upload to C2 server |
| `parsers` | ❌ | object | Output parsers to extract facts |
| `code` | ❌ | string | Source code for compiled executables |
| `language` | ❌ | string | Programming language |
| `build_target` | ❌ | string | Target executable filename |
| `variations` | ❌ | array | Alternative command implementations |

## Requirements System

Requirements control when procedures execute. They check Caldera's fact database for specific conditions before allowing execution.

### Requirement Format

| Field | Required | Description |
|-------|----------|-------------|
| `source` | ✅ | Source fact name for requirement validation |
| `edge` | ❌ | Relationship between source and target facts |
| `target` | ❌ | Target fact name for requirement validation |

### Requirement Types

| Module | Description |
|--------|-------------|
| `paw_provenance` | Requires facts from previous procedures on same agent |
| `basic` | Requires relationship between facts (source-edge-target) |
| `not_exists` | Requires absence of specific facts |
| `reachable` | Requires network reachability to target |
| `req_like` | Pattern matching requirements |
| `no_backwards_movement` | Prevents execution on source host |

## Parser System

Parsers extract structured data from command output to populate Caldera's fact database.

### Parser Format

| Field | Required | Description |
|-------|----------|-------------|
| `source` | ✅ | Primary fact name to extract |
| `edge` | ❌ | Relationship between source and target |
| `target` | ❌ | Secondary fact name |

## Global Variables

| Variable | Type | Description |
|----------|------|-------------|
| `#{server}` | System | Caldera server FQDN |
| `#{group}` | System | Agent group identifier |
| `#{paw}` | System | Unique agent identifier |
| `#{location}` | System | Agent location on filesystem |
| `#{exe_name}` | System | Agent executable name |
| `#{remote.host.fqdn}` | Fact | Target host FQDN |
| `#{domain.user.name}` | Fact | Domain username |
| `#{domain.user.password}` | Fact | Domain password |
| `#{host.user.name}` | Fact | Local username |

## Example Procedure

```yaml
- id: 12345678-1234-1234-1234-123456789abc
  name: Enumerate Running Processes
  description: Uses ps command to list all running processes
  tactic: discovery
  technique:
    attack_id: T1057
    name: Process Discovery
  platforms:
    darwin:
      sh:
        command: ps aux
        cleanup: echo "No cleanup required"
        timeout: 30
    linux:
      sh:
        command: ps aux
        timeout: 30
  buckets:
    - collection
    - host-enumeration
``` 