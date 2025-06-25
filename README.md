# Caldera Abilities Library

![Total Abilities](https://img.shields.io/badge/Total%20Abilities-2948-blue)
![Windows](https://img.shields.io/badge/Windows-2029-lightblue)
![Darwin](https://img.shields.io/badge/Darwin-463-orange)
![Linux](https://img.shields.io/badge/Linux-456-red)
![Unique Techniques](https://img.shields.io/badge/Unique%20Techniques-308-green)
![License](https://img.shields.io/badge/License-Apache%202.0-green)

The CALDERA Abilities is a library **ready-to-deploy** procedures and payloads from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [LOLBAS Project](https://github.com/LOLBAS-Project/LOLBAS), [LOLDrivers](https://github.com/magicsword-io/LOLDrivers), and [Attack-macOS](https://github.com/armadoinc/attack-macOS). All abilities are mapped to the MITRE ATT&CK knowledge base.


## Get Started



### How To Update CALDEARA abilities

```python
python3 cicd/import_atomic_index_to_caldera.py --all-platforms --payloads-dir ./payloads --force --verbose
```


## Procedure and Payload Sources
| Source | Description | Platform |
|--------|-------------|----------|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Adversary emulation test library mapped to MITRE ATT&CK | All |
| [LOLBAS Project](https://github.com/LOLBAS-Project/LOLBAS) | Windows Living Off The Land Binaries and Scripts | Windows |
| [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Malicious and vulnerable Windows drivers | Windows |
| [LOOBins](https://www.loobins.io/) | macOS Living Off the Orchard Binaries | macOS |
| [Attack-macOS](https://github.com/armadoinc/attack-macOS) | macOS post-exploitation scripts and techniques | macOS |


## Ability Schema Format

The complete schema definition is available in [schema.json](schema.json). 
All abilities use standardized YAML format with the following structure:


### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique UUID identifier |
| `name` | string | Human-readable ability name |
| `description` | string | What the ability accomplishes |
| `tactic` | string | MITRE ATT&CK tactic (discovery, execution, etc.) |
| `technique` | object | MITRE ATT&CK technique information |
| `technique.attack_id` | string | ATT&CK technique ID (T1057, T1021.006) |
| `technique.name` | string | Full ATT&CK technique name |
| `platforms` | object | Platform-specific implementations |

### Optional Fields

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

### Executor Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `command` | ✅ | string | Command to execute |
| `timeout` | ❌ | integer | Execution timeout in seconds (default: 60) |
| `cleanup` | ❌ | string | Commands to reverse ability effects |
| `payloads` | ❌ | array | Files required for execution |
| `uploads` | ❌ | array | Files to upload to C2 server |
| `parsers` | ❌ | object | Output parsers to extract facts |
| `code` | ❌ | string | Source code for compiled executables |
| `language` | ❌ | string | Programming language |
| `build_target` | ❌ | string | Target executable filename |
| `variations` | ❌ | array | Alternative command implementations |

## Requirements 

Requirements control when abilities execute. They check Caldera's fact database for specific conditions before allowing execution.

### Requirement Format

| Field | Required | Description |
|-------|----------|-------------|
| `source` | ✅ | Source fact name for requirement validation |
| `edge` | ❌ | Relationship between source and target facts |
| `target` | ❌ | Target fact name for requirement validation |

### Requirement Types

| Module | Description |
|--------|-------------|
| `paw_provenance` | Requires facts from previous abilities on same agent |
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

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Ensure all abilities follow the standardized YAML format
4. Validate your abilities using the provided schema
5. Submit a pull request with a clear description



## Acknowledgements


**Technical References**
- Caldera Documentation: https://caldera.mitre.org/
- JSON Schema Specification: https://json-schema.org/

## License

Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

