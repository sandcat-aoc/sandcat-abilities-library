## Import Scripts

These scripts import security procedures from various sources into Caldera procedure format:

| Script | Source | Platform |
|--------|--------|----------|
| `import_atomic_index_to_caldera.py` | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Windows, macOS, Linux |
| `import_attack_macos_to_caldera.py` | [Attack-macOS](https://github.com/armadoinc/caldera-plugin-attack-macos) | macOS |
| `import_lolbas_to_caldera.py` | [LOLBAS](https://lolbas-project.github.io/) | Windows |
| `import_loldrivers_to_caldera.py` | [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Windows |
| `import_loobins_to_caldera.py` | [LOOBins](https://github.com/infosecB/LOOBins) | macOS |

## Setup

Run the setup script to create virtual environment and install dependencies:
```bash
./setup_venv.sh
source venv/bin/activate
```

## Usage

Each script can be run independently:

```bash
# Import all Atomic Red Team platforms
python3 import_atomic_index_to_caldera.py --all-platforms --force

# Import Attack-macOS procedures  
python3 import_attack_macos_to_caldera.py --output ../abilities/darwin/ --force

# Import Windows living-off-the-land binaries
python3 import_lolbas_to_caldera.py --output ../abilities/windows/ 

# Import malicious Windows drivers
python3 import_loldrivers_to_caldera.py --output ../abilities/windows/

# Import macOS living-off-the-land binaries
python3 import_loobins_to_caldera.py --output ../abilities/darwin/ --force
```

Use `--help` with any script for detailed options.

## Output

Procedures are organized by tactic in the `abilities/` directory:
- `abilities/windows/[tactic]/[procedure-id].yml`
- `abilities/darwin/[tactic]/[procedure-id].yml` 
- `abilities/linux/[tactic]/[procedure-id].yml`

## Files

- `requirements.txt` - Python dependencies
- `setup_venv.sh` - Environment setup script
- `cti/enterprise-attack.json` - MITRE ATT&CK data for tactic mapping

