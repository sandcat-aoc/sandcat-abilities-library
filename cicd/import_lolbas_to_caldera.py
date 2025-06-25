#!/usr/bin/env python3
"""
Convert LOLBAS JSON to individual Caldera procedure YAML files.

This script converts Windows living-off-the-land binaries from the LOLBAS project
into individual YAML procedure files compatible with the Caldera stockpile plugin.
"""

#!/usr/bin/env python3
"""
Convert LOLBAS JSON to individual Caldera procedure YAML files.

This script converts Windows living-off-the-land binaries from the LOLBAS project
into individual YAML procedure files compatible with the Caldera stockpile plugin.
"""

import argparse
import json
import uuid
import yaml
import os
import re
import requests
import sys
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path

# Bypass proxy configuration at module level
os.environ.update({
    'NO_PROXY': '*',
    'no_proxy': '*',
    'HTTP_PROXY': '',
    'HTTPS_PROXY': '',
    'http_proxy': '',
    'https_proxy': ''
})

# Install: pip install mitreattack-python
try:
    from mitreattack.stix20 import MitreAttackData
    MITRE_AVAILABLE = True
except ImportError:
    print("ERROR: mitreattack-python not installed. Install with: pip install mitreattack-python")
    print("This is required for proper tactic mapping from technique IDs.")
    exit(1)

# Global configuration - set Caldera root directory
CALDERA_ROOT = Path(__file__).parent.parent  # Go up from cicd/ to caldera root
DEFAULT_OUTPUT_PATH = "../abilities/windows/"

def download_lolbas_data():
    """Download LOLBAS data from the official API"""
    url = "https://lolbas-project.github.io/api/lolbas.json"
    
    # Bypass proxy configuration
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'}
    proxies = {'http': None, 'https': None}
    
    response = requests.get(url, headers=headers, proxies=proxies)
    response.raise_for_status()
    return response.json()

def get_mitre_attack_data():
    """Get MITRE ATT&CK data for technique-to-tactic mapping"""
    # Use cicd directory to construct path to STIX file
    stix_file = Path(__file__).parent / "cti" / "enterprise-attack.json"
    
    if not stix_file.exists():
        print(f"ERROR: STIX file not found at {stix_file}")
        print(f"Caldera root directory: {CALDERA_ROOT}")
        return None
    
    # Load the STIX data
    try:
        print(f"Loading MITRE ATT&CK data from {stix_file}...")
        attack_data = MitreAttackData(str(stix_file))  # Convert Path to string
        return attack_data
    except Exception as e:
        print(f"Error loading MITRE ATT&CK data: {e}")
        return None

def get_tactic_from_technique_id(technique_id, attack_data):
    """Get the correct tactic from a MITRE technique ID using the ATT&CK library"""
    
    if not attack_data:
        print(f"WARNING: No ATT&CK data available, skipping technique {technique_id}")
        return None
    
    try:
        # Get all techniques
        techniques = attack_data.get_techniques()
        
        for technique in techniques:
            if hasattr(technique, 'external_references'):
                for ref in technique.external_references:
                    if (ref.source_name == 'mitre-attack' and 
                        ref.external_id == technique_id):
                        # Get kill chain phases (tactics)
                        if hasattr(technique, 'kill_chain_phases'):
                            for phase in technique.kill_chain_phases:
                                if phase.kill_chain_name == 'mitre-attack':
                                    return phase.phase_name
        
        print(f"WARNING: Technique {technique_id} not found in ATT&CK data")
        return None
        
    except Exception as e:
        print(f"Error looking up technique {technique_id}: {e}")
        return None

def convert_lolbas_placeholders(command):
    """Convert LOLBAS placeholders to Caldera fact syntax, preserving full paths"""
    conversions = {
        '{PATH}': '#{host.dir.temp}',
        '{CMD}': '#{host.executable.name}',
        '{FILE}': '#{host.file.path}',
        '{URL}': '#{host.url.target}',
        '{IP}': '#{host.ip.address}',
        '{PORT}': '#{host.port.number}',
        '{DOMAIN}': '#{host.domain.name}',
        '{USER}': '#{host.user.name}',
        '{PASS}': '#{host.user.password}',
        '{PID}': '#{host.process.id}',
        '{GUID}': '#{host.guid.value}',
        '{KEY}': '#{host.registry.key}',
        '{VALUE}': '#{host.registry.value}',
        '{SERVICE}': '#{host.service.name}',
        '{TASK}': '#{host.task.name}',
        '{LOG}': '#{host.log.path}',
        '{REMOTEURL}': '#{server}/file/download'
    }
    
    import re
    
    # Handle dynamic placeholders - preserve full paths where possible
    command = re.sub(r'\{PATH_[^}]*\.exe\}', r'payload.exe', command)
    command = re.sub(r'\{PATH_[^}]*\.dll\}', r'payload.dll', command)
    command = re.sub(r'\{PATH_[^}]*\.(bat|ps1|vbs|js)\}', r'#{host.file.script}', command)
    command = re.sub(r'\{PATH_[^}]*\.(txt|log|dat|xml|json)\}', r'#{host.file.path}', command)
    command = re.sub(r'\{PATH_[^}]*\}', r'#{host.dir.temp}', command)
    
    # Replace other patterns  
    command = re.sub(r'\{[^}]*\.exe\}', r'payload.exe', command)
    command = re.sub(r'\{[^}]*\.dll\}', r'payload.dll', command)
    command = re.sub(r'\{[^}]*\.(bat|ps1|vbs|js)\}', r'#{host.file.script}', command)
    command = re.sub(r'\{[^}]*\.(txt|log|dat|xml|json)\}', r'#{host.file.path}', command)
    
    # Replace simple placeholders
    for placeholder, fact in conversions.items():
        command = command.replace(placeholder, fact)
    
    return command

def needs_payload_file(command):
    """Determine if command needs actual payload files"""
    return 'payload.exe' in command or 'payload.dll' in command

def get_payload_files(command):
    """Extract what payload files are needed"""
    payloads = []
    if 'payload.exe' in command:
        payloads.append('payload.exe')
    if 'payload.dll' in command:
        payloads.append('payload.dll')
    return payloads

def determine_executor(command):
    """Determine executor based on command content"""
    command_lower = command.lower()
    
    powershell_indicators = [
        'powershell', 'pwsh', '$', 'get-', 'set-', 'new-', 'invoke-',
        'start-process', 'add-type', '[system.', 'import-module'
    ]
    
    if any(indicator in command_lower for indicator in powershell_indicators):
        return 'psh'
    
    return 'cmd'

def determine_privilege(command, lolbas_entry):
    """Determine required privilege level"""
    privileges = lolbas_entry.get('Privileges', [])
    if any(priv in ['Administrator', 'SYSTEM', 'Admin'] for priv in privileges):
        return 'Elevated'
    
    privilege_indicators = [
        'runas', 'elevate', 'administrator', 'system', 'admin',
        'net localgroup', 'net user', 'reg add hklm', 'sc create',
        'schtasks /create /s', 'wmic /node:'
    ]
    
    if any(indicator in command.lower() for indicator in privilege_indicators):
        return 'Elevated'
    
    return 'User'

def is_singleton_operation(command, description):
    """Determine if operation should be singleton"""
    singleton_keywords = [
        'install', 'create service', 'add', 'register', 'enable', 'disable',
        'configure', 'setup', 'initialize', 'compile', 'build'
    ]
    
    text = (command + ' ' + description).lower()
    return any(keyword in text for keyword in singleton_keywords)

def get_os_metadata(lolbas_entry):
    """Extract OS metadata from LOLBAS entry"""
    os_info = {}
    
    # Check if there's version info in LOLBAS data
    if 'SupportedOS' in lolbas_entry:
        os_info['supported_os'] = lolbas_entry['SupportedOS']
    
    # Default to generic Windows
    os_info['platform'] = 'windows'
    
    return os_info

def generate_deterministic_uuid(content: str) -> str:
    """Generate a deterministic UUID based on content hash"""
    # Create MD5 hash of the content for deterministic UUID
    hash_obj = hashlib.md5(content.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Format as proper UUID: 8-4-4-4-12
    return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"

def save_procedure_to_tactic(procedure: Dict[str, Any], base_output_dir: Path) -> bool:
    """Save procedure to tactic-specific directory (copied from atomic script pattern)"""
    tactic = procedure['tactic']
    
    # Create tactic subdirectory
    tactic_dir = base_output_dir / tactic
    tactic_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = tactic_dir / f"{procedure['id']}.yml"
    
    try:
        with open(output_file, 'w') as f:
            yaml.dump([procedure], f, default_flow_style=False, sort_keys=False)
        print(f"  Saved: {output_file}")
        return True
    except Exception as e:
        print(f"  ERROR saving {procedure['id']}: {e}")
        return False

def convert_lolbas_to_caldera(output_dir: Path):
    """Convert LOLBAS data to Caldera procedure files using proper MITRE ATT&CK mapping"""
    print("Downloading LOLBAS data...")
    lolbas_data = download_lolbas_data()
    
    print("Loading MITRE ATT&CK data...")
    attack_data = get_mitre_attack_data()
    if not attack_data:
        print("ERROR: Failed to load MITRE ATT&CK data. Cannot continue without proper tactic mapping.")
        return False
    
    print("SUCCESS: MITRE ATT&CK data loaded successfully")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")
    
    procedures_created = 0
    skipped_no_technique = 0
    tactic_counts = {}
    
    for entry in lolbas_data:
        name = entry.get('Name', 'Unknown')
        description = entry.get('Description', '')
        
        commands = entry.get('Commands', [])
        if not commands:
            continue
        
        print(f"Processing {name}...")
        
        for cmd_entry in commands:
            command = cmd_entry.get('Command', '').strip()
            if not command:
                continue
            
            cmd_description = cmd_entry.get('Description', description)
            
            # Get MITRE technique ID from LOLBAS data - REQUIRED
            attack_id = cmd_entry.get('MitreID') or entry.get('MitreID')
            
            if not attack_id:
                print(f"  Skipping {name} command - no MITRE technique ID available")
                skipped_no_technique += 1
                continue
            
            # Get correct tactic from technique ID using MITRE library - REQUIRED
            tactic = get_tactic_from_technique_id(attack_id, attack_data)
            
            if not tactic:
                print(f"  Skipping {name} command - technique {attack_id} not found in ATT&CK")
                skipped_no_technique += 1
                continue
            
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            
            # Convert placeholders
            converted_command = convert_lolbas_placeholders(command)
            
            # Get technique name from LOLBAS or use generic
            technique_name = cmd_entry.get('MitreTechnique') or entry.get('MitreTechnique') or 'System Binary Proxy Execution'
            
            # Determine executor and privilege
            executor = determine_executor(converted_command)
            privilege = determine_privilege(converted_command, entry)
            
            # Get OS metadata
            os_metadata = get_os_metadata(entry)
            
            # Use clean description since metadata is now in dedicated fields
            enhanced_description = cmd_description
            
            # Create deterministic UUID based on name and command
            uuid_content = f"{name}_{cmd_description}_{converted_command}"
            procedure_id = generate_deterministic_uuid(uuid_content)
            
            # Create procedure structure
            procedure = {
                'id': procedure_id,
                'name': f"{name} - {cmd_description}",
                'description': enhanced_description,
                'tactic': tactic,
                'technique': {
                    'attack_id': attack_id,
                    'name': technique_name
                },
                'platforms': {
                    'windows': {
                        executor: {
                            'command': converted_command
                        }
                    }
                },
                'singleton': is_singleton_operation(converted_command, cmd_description),
                'privilege': privilege,
                'repeatable': not is_singleton_operation(converted_command, cmd_description),
                'buckets': [tactic],
                # Metadata fields
                'version': '1.0',
                'author': entry.get('Author', 'LOLBAS Project'),
                'created': entry.get('Created', 'Unknown'),
                'modified': entry.get('Modified', entry.get('Created', 'Unknown')),
                'operating_system': f"Windows {entry.get('SupportedOS', 'All Versions')}"
            }
            
            # Add payloads section if needed
            if needs_payload_file(converted_command):
                payload_files = get_payload_files(converted_command)
                if payload_files:
                    procedure['platforms']['windows'][executor]['payloads'] = payload_files
            
            # Save to tactic directory like atomic script
            if save_procedure_to_tactic(procedure, output_dir):
                procedures_created += 1
    
    print(f"\nSUCCESS: Created {procedures_created} Caldera procedures in {output_dir}")
    print(f"WARNING: Skipped {skipped_no_technique} commands without valid MITRE technique IDs")
    print("\nTactic distribution:")
    for tactic, count in sorted(tactic_counts.items()):
        print(f"  {tactic}: {count}")
    
    return True

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Convert LOLBAS data to Caldera procedure YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Use default output path
  %(prog)s -o ./procedures/                    # Output to local directory
  %(prog)s --output /path/to/procedures/       # Output to specific path
  %(prog)s --caldera-root /path/to/caldera/   # Use different Caldera installation
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path.cwd(),
        help=f'Output directory for procedure files (default: current directory)'
    )
    
    parser.add_argument(
        '--caldera-root',
        type=Path,
        default=CALDERA_ROOT,
        help=f'Path to Caldera root directory (default: {CALDERA_ROOT})'
    )
    
    parser.add_argument(
        '--use-default-path',
        action='store_true',
        help=f'Use default library path: {DEFAULT_OUTPUT_PATH}'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Update global CALDERA_ROOT if specified
    global CALDERA_ROOT
    CALDERA_ROOT = args.caldera_root
    
    # Determine output directory
    if args.use_default_path:
        output_dir = Path(DEFAULT_OUTPUT_PATH)
    else:
        output_dir = args.output
    
    if args.verbose:
        print(f"Caldera root: {CALDERA_ROOT}")
        print(f"Output directory: {output_dir}")
    
    # Convert LOLBAS data
    success = convert_lolbas_to_caldera(output_dir)
    
    if success:
        print(f"\n✅ Conversion completed successfully!")
        sys.exit(0)
    else:
        print(f"\n❌ Conversion failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 