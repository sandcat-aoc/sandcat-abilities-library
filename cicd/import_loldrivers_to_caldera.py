#!/usr/bin/env python3
"""
Convert LOLDrivers YAML to individual Caldera procedure YAML files.

This script converts malicious Windows drivers from the LOLDrivers project
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
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib

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
    MITRE_AVAILABLE = False

# Global configuration
CALDERA_ROOT = Path(__file__).parent.parent
DEFAULT_OUTPUT_PATH = "../abilities/windows/"

# LOLDrivers GitHub API endpoints
LOLDRIVERS_YAML_API = "https://api.github.com/repos/magicsword-io/LOLDrivers/contents/yaml"
LOLDRIVERS_DRIVERS_API = "https://api.github.com/repos/magicsword-io/LOLDrivers/contents/drivers"
LOLDRIVERS_REPO_URL = "https://github.com/magicsword-io/LOLDrivers.git"

def download_loldrivers_yaml_list():
    """Get list of LOLDrivers YAML files from GitHub API"""
    try:
        # Bypass proxy configuration
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'}
        proxies = {'http': None, 'https': None}
        
        response = requests.get(LOLDRIVERS_YAML_API, headers=headers, proxies=proxies)
        response.raise_for_status()
        files = response.json()
        
        yaml_files = [f for f in files if f['name'].endswith('.yaml') or f['name'].endswith('.yml')]
        print(f"Found {len(yaml_files)} LOLDrivers YAML files")
        return yaml_files
        
    except Exception as e:
        print(f"ERROR: Failed to get LOLDrivers file list: {e}")
        return []

def download_loldrivers_drivers_list():
    """Get list of driver binaries from LOLDrivers repository"""
    try:
        # Bypass proxy configuration
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'}
        proxies = {'http': None, 'https': None}
        
        response = requests.get(LOLDRIVERS_DRIVERS_API, headers=headers, proxies=proxies)
        response.raise_for_status()
        drivers = response.json()
        print(f"Found {len(drivers)} LOLDrivers binary files")
        return drivers
    except Exception as e:
        print(f"WARNING: Failed to get LOLDrivers drivers list: {e}")
        return []

def get_mitre_attack_data():
    """Get MITRE ATT&CK data for technique-to-tactic mapping"""
    if not MITRE_AVAILABLE:
        return None
        
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
        print(f"ERROR: No ATT&CK data available for technique {technique_id}, cannot determine tactic")
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
        
        print(f"ERROR: Technique {technique_id} not found in ATT&CK data")
        return None
        
    except Exception as e:
        print(f"ERROR: Failed to lookup technique {technique_id}: {e}")
        return None

def download_loldriver_yaml(file_info: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Download and parse a single LOLDriver YAML file"""
    try:
        # Bypass proxy configuration
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'}
        proxies = {'http': None, 'https': None}
        
        response = requests.get(file_info['download_url'], headers=headers, proxies=proxies)
        response.raise_for_status()
        
        # Parse YAML content
        driver_data = yaml.safe_load(response.text)
        return driver_data
        
    except Exception as e:
        print(f"WARNING: Failed to download {file_info['name']}: {e}")
        return None

def extract_dates_info(driver_data: Dict[str, Any], verbose: bool = False) -> tuple:
    """Extract and validate creation/modification dates from LOLDrivers data"""
    created = driver_data.get('Created', 'Unknown')
    modified = driver_data.get('Modified', created if created != 'Unknown' else 'Unknown')
    
    if verbose and created != 'Unknown':
        print(f"    Date info - Created: {created}, Modified: {modified}")
    elif verbose:
        print(f"    Date info - No dates available in source data")
    
    return created, modified

def extract_os_info(driver_data: Dict[str, Any]) -> str:
    """Extract accurate operating system information from LOLDrivers data"""
    # Check for specific OS information in the data
    if 'SupportedOS' in driver_data:
        return f"Windows {driver_data['SupportedOS']}"
    
    # Check if there are OS-specific samples
    samples = driver_data.get('KnownVulnerableSamples', [])
    if samples:
        # Look for OS information in samples
        for sample in samples:
            if 'OperatingSystem' in sample:
                return f"Windows {sample['OperatingSystem']}"
            if 'OS' in sample:
                return f"Windows {sample['OS']}"
    
    # Check for version-specific information in tags or category
    tags = driver_data.get('Tags', [])
    if isinstance(tags, list):
        for tag in tags:
            if 'windows' in str(tag).lower():
                # Try to extract version from tag
                tag_str = str(tag).lower()
                if '10' in tag_str:
                    return 'Windows 10+'
                elif '11' in tag_str:
                    return 'Windows 11'
                elif '7' in tag_str:
                    return 'Windows 7+'
    
    # Default fallback with more generic description
    return 'Windows (Version Unspecified)'

def format_as_uuid(id_string: str) -> str:
    """Format a string as a proper UUID with dashes for readability"""
    # Remove any existing dashes and clean the string
    clean_id = id_string.replace('-', '').replace(' ', '').lower()
    
    # If it's exactly 32 characters (like MD5), format as UUID
    if len(clean_id) == 32 and all(c in '0123456789abcdef' for c in clean_id):
        # Format as UUID: 8-4-4-4-12
        return f"{clean_id[:8]}-{clean_id[8:12]}-{clean_id[12:16]}-{clean_id[16:20]}-{clean_id[20:32]}"
    
    # If it's already close to UUID format, just ensure proper format
    if len(clean_id) == 32:
        return f"{clean_id[:8]}-{clean_id[8:12]}-{clean_id[12:16]}-{clean_id[16:20]}-{clean_id[20:32]}"
    
    # Otherwise, generate a new UUID but keep it deterministic based on input
    hash_obj = hashlib.md5(clean_id.encode())
    hash_hex = hash_obj.hexdigest()
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

def find_corresponding_driver(yaml_id: str, drivers_list: List[Dict]) -> Optional[str]:
    """Find the corresponding driver binary for a YAML entry"""
    if not drivers_list:
        return None
        
    for driver in drivers_list:
        driver_name = driver.get('name', '')
        # Remove extension and compare with YAML ID
        driver_base = os.path.splitext(driver_name)[0].lower()
        if yaml_id.lower() == driver_base or yaml_id.lower() in driver_name.lower():
            return driver_name
    return None

def convert_loldriver_to_caldera(driver_data: Dict[str, Any], filename: str, verbose: bool = False, driver_filename: Optional[str] = None, attack_data=None) -> Optional[Dict[str, Any]]:
    """Convert LOLDriver data to Caldera procedure format"""
    
    try:
        # Extract basic information
        driver_name = driver_data.get('Name', filename.replace('.yaml', '').replace('.yml', ''))
        description = driver_data.get('Description', f"Malicious driver: {driver_name}")
        
        # Create enhanced description with metadata
        enhanced_description = description
        
        # Add metadata if available
        if 'Category' in driver_data:
            enhanced_description += f"\nCategory: {driver_data['Category']}"
        
        if 'Author' in driver_data:
            enhanced_description += f"\nAuthor: {driver_data['Author']}"
            
        if 'Created' in driver_data:
            enhanced_description += f"\nCreated: {driver_data['Created']}"
            
        # Add threat information
        if 'MitreID' in driver_data:
            enhanced_description += f"\nMITRE Technique: {driver_data['MitreID']}"
            
        # Extract command patterns - LOLDrivers often have deployment/usage commands
        commands = []
        
        # Check for various command fields
        if 'Commands' in driver_data:
            if isinstance(driver_data['Commands'], list):
                commands.extend(driver_data['Commands'])
            elif isinstance(driver_data['Commands'], str):
                commands.append(driver_data['Commands'])
                
        # Check for deployment instructions
        if 'Usecase' in driver_data and isinstance(driver_data['Usecase'], str):
            commands.append(driver_data['Usecase'])
            
        # If no specific commands, create a generic driver loading command
        if not commands:
            # Use actual driver filename if available from binary matching
            if driver_filename:
                binary_name = driver_filename
                # Create comprehensive deployment command with binary download
                commands = [
                    f"certutil.exe -urlcache -split -f #{{{{{binary_name}}}}} %TEMP%\\{binary_name}",
                    f"sc create MaliciousDriver binPath= \"%TEMP%\\{binary_name}\" type= kernel",
                    f"sc start MaliciousDriver"
                ]
            else:
                # Fallback to generic command
                fallback_name = driver_data.get('DriverFileName', 'malicious_driver.sys')
                commands = [
                    f"sc create MaliciousDriver binPath= \"C:\\Windows\\System32\\drivers\\{fallback_name}\" type= kernel",
                    f"sc start MaliciousDriver"
                ]
        
        # Use first command for the procedure, or create multi-step command if we have binary
        if driver_filename and len(commands) > 1:
            main_command = " && ".join(commands)
        else:
            main_command = commands[0] if commands else f"# Deploy {driver_name} driver"
        
        # Convert any placeholders to Caldera facts
        main_command = convert_driver_placeholders(main_command)
        
        # Determine MITRE ATT&CK info
        attack_id = driver_data.get('MitreID', 'T1014')  # Default to rootkit technique
        technique_name = driver_data.get('MitreTechnique', 'Rootkit')
        
        # Get correct tactic from technique ID using MITRE library
        tactic = get_tactic_from_technique_id(attack_id, attack_data)
        
        if not tactic:
            print(f"    SKIPPED: Cannot determine tactic for {attack_id}")
            return None
        
        if verbose:
            print(f"    MITRE Technique: {attack_id} → Tactic: {tactic}")
        
        # Use original ID from LOLDrivers YAML, format as proper UUID
        original_id = driver_data.get('Id', filename.replace('.yaml', '').replace('.yml', ''))
        formatted_id = format_as_uuid(original_id)
        
        # Create procedure structure
        procedure = {
            'id': formatted_id,
            'name': f"{driver_name} - Malicious Driver Deployment",
            'description': enhanced_description,
            'tactic': tactic,
            'technique': {
                'attack_id': attack_id,
                'name': technique_name
            },
            'platforms': {
                'windows': {
                    'cmd': {
                        'command': main_command
                    }
                }
            },
            'singleton': True,  # Driver deployment should typically be singleton
            'privilege': 'Elevated',  # Driver operations require admin
            'repeatable': False,
            'buckets': [tactic],
            # Metadata fields
            'version': '1.0', #TODO: version is hard coded, not good.
            'author': driver_data.get('Author', 'LOLDrivers Project'),
            'operating_system': extract_os_info(driver_data)
        }
        
        # Extract accurate dates
        created, modified = extract_dates_info(driver_data, verbose)
        procedure['created'] = created
        procedure['modified'] = modified
        
        if verbose:
            os_info = extract_os_info(driver_data)
            print(f"    OS info: {os_info}")
            if os_info == 'Windows (Version Unspecified)':
                print(f"    Available data fields: {list(driver_data.keys())}")
        
        # Add driver file as payload if we have a matched binary
        if driver_filename:
            # Add the actual driver binary as payload
            procedure['platforms']['windows']['cmd']['payloads'] = [driver_filename]
            if verbose:
                print(f"    Added payload: {driver_filename}")
        else:
            # Check if there's a driver filename in the data for generic payload
            data_driver_filename = driver_data.get('DriverFileName')
            if data_driver_filename and data_driver_filename.lower() in main_command.lower():
                # Replace actual filename with generic payload reference
                procedure['platforms']['windows']['cmd']['command'] = main_command.replace(
                    data_driver_filename, 'malicious_driver.sys'
                )
                procedure['platforms']['windows']['cmd']['payloads'] = ['malicious_driver.sys']
        
        return procedure
        
    except Exception as e:
        print(f"ERROR: Failed to convert {filename}: {e}")
        return None

def clone_loldrivers_repo(verbose: bool = False) -> Optional[Path]:
    """Clone LOLDrivers repository for driver binary access"""
    try:
        import tempfile
        temp_dir = tempfile.mkdtemp()
        repo_path = Path(temp_dir) / 'loldrivers'
        
        if verbose:
            print("  Cloning LOLDrivers repository for driver binaries...")
        
        # Set environment to bypass proxy
        env = os.environ.copy()
        env.update({
            'NO_PROXY': '*',
            'no_proxy': '*', 
            'HTTP_PROXY': '',
            'HTTPS_PROXY': '',
            'http_proxy': '',
            'https_proxy': ''
        })
        
        # Try cloning with master branch first, then main
        for branch in ['main', 'master']:
            try:
                result = subprocess.run(['git', 'clone', '--depth=1', '--branch', branch, 
                                       LOLDRIVERS_REPO_URL, str(repo_path)], 
                                      capture_output=True, text=True, timeout=120, env=env)
                if result.returncode == 0:
                    if verbose:
                        print(f"    Successfully cloned LOLDrivers repository ({branch} branch)")
                    return repo_path
            except subprocess.TimeoutExpired:
                if verbose:
                    print(f"    Timeout cloning LOLDrivers with {branch} branch")
                continue
            except subprocess.CalledProcessError:
                if verbose:
                    print(f"    Failed cloning LOLDrivers with {branch} branch")
                continue
        
        print(f"  WARNING: Failed to clone LOLDrivers repository")
        return None
        
    except Exception as e:
        print(f"  ERROR: Failed to setup LOLDrivers repo: {e}")
        return None

def copy_driver_payload(yaml_id: str, driver_filename: str, repo_path: Path, payloads_dir: Path, verbose: bool = False) -> bool:
    """Copy driver binary from repository to payloads directory"""
    if not repo_path or not payloads_dir:
        return False
    
    try:
        # Look for driver in the drivers directory
        drivers_dir = repo_path / 'drivers'
        if not drivers_dir.exists():
            if verbose:
                print(f"    Drivers directory not found in repository")
            return False
        
        # Find the driver file (case-insensitive search)
        driver_files = list(drivers_dir.rglob('*'))
        matched_file = None
        
        for file_path in driver_files:
            if file_path.is_file() and file_path.name.lower() == driver_filename.lower():
                matched_file = file_path
                break
        
        if not matched_file:
            if verbose:
                print(f"    Driver file not found: {driver_filename}")
            return False
        
        # Create payloads directory
        payloads_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy driver to payloads directory
        dst_file = payloads_dir / driver_filename
        
        if not dst_file.exists():
            import shutil
            shutil.copy2(matched_file, dst_file)
            if verbose:
                print(f"    Copied driver payload: {driver_filename}")
            return True
        else:
            if verbose:
                print(f"    Driver payload exists: {driver_filename}")
            return True
            
    except Exception as e:
        if verbose:
            print(f"    Error copying driver {driver_filename}: {e}")
        return False

def convert_driver_placeholders(command: str) -> str:
    """Convert driver-specific placeholders to Caldera facts"""
    conversions = {
        '{DRIVER_PATH}': '#{host.dir.system}\\drivers\\',
        '{DRIVER_NAME}': '#{host.service.name}',
        '{SERVICE_NAME}': '#{host.service.name}',
        '{SYSTEM_ROOT}': '#{host.dir.system}',
        '{TEMP_PATH}': '#{host.dir.temp}',
    }
    
    for placeholder, fact in conversions.items():
        command = command.replace(placeholder, fact)
    
    return command

def convert_loldrivers_to_caldera(output_dir: Path, payloads_dir: Optional[Path] = None, limit: Optional[int] = None, verbose: bool = False):
    """Convert LOLDrivers data to Caldera procedure files"""
    
    print("Loading MITRE ATT&CK data...")
    attack_data = get_mitre_attack_data()
    if not attack_data:
        if MITRE_AVAILABLE:
            print("ERROR: Failed to load MITRE ATT&CK data. Cannot continue without proper tactic mapping.")
            print("       Download enterprise-attack.json from https://github.com/mitre/cti")
        else:
            print("ERROR: mitreattack-python not available. Install with: pip install mitreattack-python")
        print("       LOLDrivers procedures will be skipped due to missing tactic mapping data.")
        return False
    else:
        print("SUCCESS: MITRE ATT&CK data loaded successfully")
    
    # Clone LOLDrivers repository for driver binaries if payloads directory specified
    repo_path = None
    if payloads_dir:
        print("Cloning LOLDrivers repository for driver binaries...")
        repo_path = clone_loldrivers_repo(verbose)
        if repo_path:
            print("  SUCCESS: Repository cloned for driver payload access")
        else:
            print("  WARNING: Failed to clone repository, driver payloads will not be copied")
    
    print("Fetching LOLDrivers YAML file list...")
    yaml_files = download_loldrivers_yaml_list()
    
    print("Fetching LOLDrivers driver binaries list...")
    drivers_list = download_loldrivers_drivers_list()
    
    if not yaml_files:
        print("ERROR: No LOLDrivers YAML files found")
        return False
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")
    
    # Limit files for testing if specified
    if limit:
        yaml_files = yaml_files[:limit]
        print(f"Processing first {limit} files only")
    
    procedures_created = 0
    skipped_count = 0
    
    for file_info in yaml_files:
        filename = file_info['name']
        if verbose:
            print(f"Processing {filename}...")
        else:
            print(f"Processing {filename}...")
        
        # Download and parse YAML
        driver_data = download_loldriver_yaml(file_info)
        if not driver_data:
            skipped_count += 1
            continue
        
        # Find corresponding driver binary
        yaml_id = os.path.splitext(filename)[0]
        driver_filename = find_corresponding_driver(yaml_id, drivers_list)
        if driver_filename and verbose:
            print(f"    Matched driver binary: {driver_filename}")
        elif verbose:
            print(f"    No matching driver binary found")
        
        # Copy driver payload if we have repo access and a matched driver
        if driver_filename and repo_path and payloads_dir:
            copy_driver_payload(yaml_id, driver_filename, repo_path, payloads_dir, verbose)
        
        # Convert to Caldera procedure - pass verbose parameter, driver info, and attack data
        procedure = convert_loldriver_to_caldera(driver_data, filename, verbose, driver_filename, attack_data)
        if not procedure:
            skipped_count += 1
            continue
        
        # Save to tactic directory like atomic script
        if save_procedure_to_tactic(procedure, output_dir):
            procedures_created += 1
    
    print(f"\nSUCCESS: Created {procedures_created} LOLDrivers procedures")
    print(f"WARNING: Skipped {skipped_count} files")
    print(f"Output directory: {output_dir}")
    
    return True

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Convert LOLDrivers YAML to Caldera procedure files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Use default output path
  %(prog)s -o ./drivers/                      # Output to local directory
  %(prog)s --limit 10                        # Process only first 10 files
  %(prog)s --use-default-path                # Use default library path
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path(DEFAULT_OUTPUT_PATH),
        help=f'Output directory for procedure files (default: {DEFAULT_OUTPUT_PATH})'
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
        '--payloads-dir',
        type=Path,
        help='Directory to copy driver payload files to (enables driver binary copying)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of files to process (for testing)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without actually creating files'
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
        if args.payloads_dir:
            print(f"Payloads directory: {args.payloads_dir}")
        if args.limit:
            print(f"Processing limit: {args.limit} files")
        if args.dry_run:
            print("DRY RUN MODE - No files will be created")
    
    if args.dry_run:
        # Just show what would be done
        print("Fetching LOLDrivers YAML file list...")
        yaml_files = download_loldrivers_yaml_list()
        
        if args.limit:
            yaml_files = yaml_files[:args.limit]
            
        print(f"Would process {len(yaml_files)} LOLDrivers files")
        print(f"Would create procedures in: {output_dir}")
        return
    
    # Convert LOLDrivers data - pass verbose parameter and payloads directory
    success = convert_loldrivers_to_caldera(output_dir, args.payloads_dir, args.limit, args.verbose)
    
    if success:
        print("Conversion completed successfully!")
        sys.exit(0)
    else:
        print("Conversion failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 