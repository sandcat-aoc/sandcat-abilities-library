#!/usr/bin/env python3
"""
Import Attack-macOS procedures to Caldera procedure library.

This script processes Attack-macOS Caldera plugin abilities and enhances them with
standard metadata and structure for the Caldera procedures library. It also copies
the associated payload files to the main repository.
"""

import argparse
import datetime
import hashlib
import os
import re
import tempfile
import yaml
import subprocess
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path

# Attack-macOS Caldera plugin repository
ATTACK_MACOS_PLUGIN_URL = 'https://github.com/armadoinc/caldera-plugin-attack-macos.git'


def generate_deterministic_uuid(content: str) -> str:
    """Generate a deterministic UUID based on content hash"""
    # Create MD5 hash of the content for deterministic UUID
    hash_obj = hashlib.md5(content.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Format as proper UUID: 8-4-4-4-12
    return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"


def get_mitre_attack_data():
    """Get MITRE ATT&CK data using the mitreattack library"""
    try:
        from mitreattack.stix20 import MitreAttackData
        
        # Use the included STIX file
        stix_file = os.path.join(os.path.dirname(__file__), "cti", "enterprise-attack.json")
        if os.path.exists(stix_file):
            return MitreAttackData(stix_file)
        else:
            # Fallback to downloading
            return MitreAttackData("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    except Exception:
        return None


def get_tactic_from_technique_id(technique_id: str) -> str:
    """Get tactic from technique ID using MITRE ATT&CK data"""
    try:
        mitre_data = get_mitre_attack_data()
        if not mitre_data:
            return None
            
        techniques = mitre_data.get_techniques()
        for technique in techniques:
            if hasattr(technique, 'external_references'):
                for ref in technique.external_references:
                    if hasattr(ref, 'external_id') and ref.external_id == technique_id:
                        # Get kill chain phases (tactics)
                        if hasattr(technique, 'kill_chain_phases'):
                            for phase in technique.kill_chain_phases:
                                if hasattr(phase, 'phase_name'):
                                    return phase.phase_name.replace('-', '-')
        return None
    except Exception:
        return None


def get_technique_name(technique_id: str) -> str:
    """Get technique name for a given technique ID using MITRE ATT&CK data"""
    try:
        mitre_data = get_mitre_attack_data()
        if not mitre_data:
            return f'Unknown Technique ({technique_id})'
            
        techniques = mitre_data.get_techniques()
        for technique in techniques:
            if hasattr(technique, 'external_references'):
                for ref in technique.external_references:
                    if hasattr(ref, 'external_id') and ref.external_id == technique_id:
                        return getattr(technique, 'name', f'Unknown Technique ({technique_id})')
        return f'Unknown Technique ({technique_id})'
    except Exception:
        return f'Unknown Technique ({technique_id})'


def determine_tactic(technique_id: str, script_content: str = "", script_name: str = "") -> str:
    """Determine tactic based on technique ID using MITRE ATT&CK data with fallbacks"""
    
    # First try to get tactic from MITRE ATT&CK data
    tactic = get_tactic_from_technique_id(technique_id)
    if tactic:
        return tactic
    
    # Try with base technique ID (e.g., T1059 from T1059.004)
    base_technique = technique_id.split('.')[0]
    if base_technique != technique_id:
        tactic = get_tactic_from_technique_id(base_technique)
        if tactic:
            return tactic
    
    # Content-based fallback detection
    content_lower = script_content.lower()
    name_lower = script_name.lower()
    
    # Discovery keywords
    if any(keyword in content_lower or keyword in name_lower for keyword in 
           ['ps ', 'netstat', 'ifconfig', 'whoami', 'id ', 'groups', 'find', 'ls ', 'system_profiler', 'uname']):
        return 'discovery'
    
    # Credential access keywords
    if any(keyword in content_lower or keyword in name_lower for keyword in 
           ['keychain', 'password', 'credential', 'security find']):
        return 'credential-access'
    
    # Collection keywords
    if any(keyword in content_lower or keyword in name_lower for keyword in 
           ['screencapture', 'pbpaste', 'clipboard']):
        return 'collection'
    
    # Defense evasion keywords
    if any(keyword in content_lower or keyword in name_lower for keyword in 
           ['hidden', 'chflags', 'xattr', 'quarantine']):
        return 'defense-evasion'
    
    # Persistence keywords
    if any(keyword in content_lower or keyword in name_lower for keyword in 
           ['launchctl', 'plist', 'startup', 'login']):
        return 'persistence'
    
    # Default to execution
    return 'execution'





def save_procedure_to_tactic(procedure: Dict[str, Any], base_output_dir: str, verbose: bool = False, force: bool = False) -> bool:
    """Save procedure to tactic-specific directory (copied from other scripts)"""
    tactic = procedure['tactic']
    
    # Create tactic subdirectory
    tactic_dir = os.path.join(base_output_dir, tactic)
    os.makedirs(tactic_dir, exist_ok=True)
    
    output_file = os.path.join(tactic_dir, f"{procedure['id']}.yml")
    
    # Check if file exists and force flag
    if os.path.exists(output_file) and not force:
        if verbose:
            print(f"  SKIPPED: {output_file} (use --force to overwrite)")
        return False
    
    try:
        # Wrap in array as required by schema
        yaml_content = [procedure]
        
        with open(output_file, 'w') as f:
            yaml.dump(yaml_content, f, default_flow_style=False, allow_unicode=True, 
                     sort_keys=False, width=100)
        if verbose:
            print(f"  Saved: {output_file}")
        return True
    except Exception as e:
        print(f"  ERROR saving {procedure['id']}: {e}")
        return False


def copy_payloads(plugin_dir: str, target_payloads_dir: str, verbose: bool = False) -> bool:
    """Copy payloads from plugin to main repository"""
    try:
        plugin_payloads = os.path.join(plugin_dir, "attackmacos", "data", "payloads")
        if not os.path.exists(plugin_payloads):
            print("  No payloads directory found in plugin")
            return False
        
        os.makedirs(target_payloads_dir, exist_ok=True)
        
        copied_count = 0
        for item in os.listdir(plugin_payloads):
            src = os.path.join(plugin_payloads, item)
            dst = os.path.join(target_payloads_dir, item)
            
            if os.path.isfile(src):
                # Copy file if it doesn't exist or is different
                if not os.path.exists(dst):
                    import shutil
                    shutil.copy2(src, dst)
                    copied_count += 1
                    if verbose:
                        print(f"    Copied payload: {item}")
        
        if copied_count > 0:
            print(f"  Copied {copied_count} payload files")
        else:
            print("  No new payloads to copy")
        return True
        
    except Exception as e:
        print(f"  ERROR copying payloads: {e}")
        return False


def enhance_procedure_yaml(yaml_file: Path, verbose: bool = False, force: bool = False, output_dir: str = "") -> Optional[Dict]:
    """Enhance existing plugin YAML file with our standard metadata"""
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            procedures = yaml.safe_load(f)
        
        if not procedures or not isinstance(procedures, list):
            if verbose:
                print(f"  SKIPPED: Invalid YAML structure")
            return None
        
        procedure = procedures[0]  # Get first procedure
        
        # Preserve existing ID
        procedure_id = procedure.get('id')
        if not procedure_id:
            if verbose:
                print(f"  SKIPPED: No ID found")
            return None
        
        # Check if file already exists (GUID preservation)
        tactic = procedure.get('tactic', 'execution')
        expected_file = os.path.join(output_dir, tactic, f"{procedure_id}.yml")
        if os.path.exists(expected_file) and not force:
            if verbose:
                print(f"  SKIPPED: File exists (use --force to overwrite)")
            return None
        
        # Enhance with our standard fields (preserve existing values)
        if 'singleton' not in procedure:
            procedure['singleton'] = should_be_singleton_from_procedure(procedure)
        
        if 'privilege' not in procedure:
            procedure['privilege'] = get_required_privilege_from_procedure(procedure)
        
        if 'repeatable' not in procedure:
            procedure['repeatable'] = not procedure.get('singleton', False)
        
        if 'delete_payload' not in procedure:
            procedure['delete_payload'] = False  # Default to false
        
        # Add/enhance buckets
        existing_buckets = procedure.get('buckets', [])
        new_buckets = ['attack-macos', tactic]
        technique_id = procedure.get('technique', {}).get('attack_id')
        if technique_id:
            new_buckets.append(technique_id.lower())
        
        # Merge buckets (avoid duplicates)
        all_buckets = list(dict.fromkeys(existing_buckets + new_buckets))
        procedure['buckets'] = all_buckets
        
        # Add metadata fields (preserve existing)
        if 'version' not in procedure:
            procedure['version'] = "1.0"
        
        if 'author' not in procedure:
            procedure['author'] = "Attack-macOS Project"
        
        # Add additional_info
        additional_info = procedure.get('additional_info', {})
        additional_info.update({
            "source_file": yaml_file.name,
            "source_repository": "https://github.com/armadoinc/caldera-plugin-attack-macos",
            "import_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            "original_plugin": "caldera-plugin-attack-macos"
        })
        procedure['additional_info'] = additional_info
        
        return procedure
        
    except Exception as e:
        if verbose:
            print(f"  ERROR processing {yaml_file}: {e}")
        return None


def should_be_singleton_from_procedure(procedure: Dict[str, Any]) -> bool:
    """Determine if procedure should be singleton based on existing data"""
    name = procedure.get('name', '').lower()
    description = procedure.get('description', '').lower()
    tactic = procedure.get('tactic', '')
    
    # Operations that should only run once
    singleton_indicators = [
        'disable', 'enable', 'install', 'uninstall', 'create', 'delete',
        'modify', 'configure', 'setup', 'init'
    ]
    
    if any(indicator in name or indicator in description for indicator in singleton_indicators):
        return True
    
    # Impact and persistence operations typically should be singleton
    if tactic in ['impact', 'persistence']:
        return True
        
    return False


def get_required_privilege_from_procedure(procedure: Dict[str, Any]) -> str:
    """Determine required privilege level from procedure data"""
    name = procedure.get('name', '').lower()
    description = procedure.get('description', '').lower()
    
    # Check for commands in platforms
    platforms = procedure.get('platforms', {})
    for platform_data in platforms.values():
        for executor_data in platform_data.values():
            command = executor_data.get('command', '').lower()
            if any(indicator in command for indicator in 
                   ['sudo ', '/library/', '/system/', 'system.keychain', 'spctl --master', 'csrutil']):
                return "Elevated"
    
    # Check name and description for admin indicators
    if any(indicator in name or indicator in description for indicator in 
           ['admin', 'root', 'system', 'privilege']):
        return "Elevated"
    
    return "User"


def find_ability_files(repo_dir: Path) -> List[Path]:
    """Find all YAML ability files in the Attack-macOS plugin repository"""
    ability_files = []
    
    # Look for YAML files in the abilities directory
    abilities_dir = repo_dir / "attackmacos" / "data" / "abilities"
    if not abilities_dir.exists():
        return ability_files
    
    # Find all YAML files recursively
    for yaml_file in abilities_dir.rglob("*.yml"):
        if yaml_file.is_file() and yaml_file.stat().st_size > 0:
            ability_files.append(yaml_file)
    
    return ability_files


def convert_attack_macos_to_caldera(repo_url: str, output_dir: str, payloads_dir: str, limit: Optional[int] = None, verbose: bool = False, force: bool = False) -> bool:
    """Main conversion function."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Set up environment to bypass proxy
    env = os.environ.copy()
    env.update({
        'NO_PROXY': '*',
        'no_proxy': '*',
        'HTTP_PROXY': '',
        'HTTPS_PROXY': '',
        'http_proxy': '',
        'https_proxy': ''
    })
    
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, "attack-macos-plugin")
        
        if verbose:
            print(f"Cloning Attack-macOS plugin from {repo_url}...")
        else:
            print(f"Cloning Attack-macOS plugin...")
            
        try:
            subprocess.run(['git', 'clone', '--depth=1', repo_url, repo_dir], 
                         check=True, env=env, capture_output=True, text=True)
            
            # Copy payloads first
            print("Checking for payloads...")
            payload_result = copy_payloads(repo_dir, payloads_dir, verbose)
            if not payload_result and verbose:
                print("  No payloads found in plugin")
            
            # Find ability YAML files
            ability_files = find_ability_files(Path(repo_dir))
            
            if limit:
                ability_files = ability_files[:limit]
                if verbose:
                    print(f"Processing first {limit} abilities only")
            
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to clone Attack-macOS plugin: {e}")
            if e.stderr:
                print(f"       stderr: {e.stderr}")
            return False
        except Exception as e:
            print(f"ERROR: Failed to process Attack-macOS plugin: {e}")
            return False
    
        print(f"Processing {len(ability_files)} abilities from Attack-macOS plugin")
        if verbose:
            print(f"Output directory: {output_dir}")
        
        total_procedures = 0
        skipped_existing = 0
        errors = 0
        
        for ability_file in ability_files:
            ability_name = ability_file.name
            if verbose:
                print(f"\nProcessing ability: {ability_name}")
            else:
                print(f"Processing {ability_name}...")
            
            try:
                procedure = enhance_procedure_yaml(ability_file, verbose, force, output_dir)
                if procedure:
                    if save_procedure_to_tactic(procedure, output_dir, verbose, force):
                        total_procedures += 1
                    else:
                        skipped_existing += 1
                else:
                    if verbose:
                        print(f"  SKIPPED: No procedure created")
            except Exception as e:
                errors += 1
                if verbose:
                    print(f"  ERROR processing {ability_name}: {e}")
                continue
        
        print(f"\nSUCCESS: Created {total_procedures} Attack-macOS procedures")
        if skipped_existing > 0:
            print(f"WARNING: Skipped {skipped_existing} existing procedures (use --force to overwrite)")
        if errors > 0:
            print(f"WARNING: {errors} abilities had errors during processing")
        if verbose:
            print(f"Output directory: {output_dir}")
        
        return True


def parse_arguments():
    """Parse command line arguments"""
    
    parser = argparse.ArgumentParser(
        description="Convert Attack-macOS repository to Caldera procedure files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
          %(prog)s --output ../abilities/darwin/   # Clone plugin and output to darwin
  %(prog)s --payloads-dir ../payloads/      # Specify payloads directory
  %(prog)s --verbose --force                # Verbose mode, overwrite existing
  %(prog)s --limit 10                       # Process only first 10 abilities
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default="../abilities/darwin/",
        help='Output directory for procedure files (default: ../abilities/darwin/)'
    )
    
    parser.add_argument(
        '--repo-url',
        type=str,
        default=ATTACK_MACOS_PLUGIN_URL,
        help='Attack-macOS plugin repository URL (default: official plugin repo)'
    )
    
    parser.add_argument(
        '--payloads-dir',
        type=str,
        default="../payloads/",
        help='Directory to copy payloads to (default: ../payloads/)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of scripts to process (for testing)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing files'
    )
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    if args.verbose:
        print(f"Attack-macOS repository: {args.repo_url}")
        print(f"Output directory: {args.output}")
        if args.limit:
            print(f"Processing limit: {args.limit} scripts")
        if args.force:
            print("Force mode: Will overwrite existing files")
    
    # Convert Attack-macOS abilities
    success = convert_attack_macos_to_caldera(args.repo_url, args.output, args.payloads_dir, args.limit, args.verbose, args.force)
    
    if success:
        print("Conversion completed successfully!")
        return 0
    else:
        print("Conversion failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 