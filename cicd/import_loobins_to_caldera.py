#!/usr/bin/env python3
"""
Convert loobins.json to individual Caldera procedure YAML files.

This script converts macOS living-off-the-land binaries from loobins.json
into individual YAML procedure files compatible with the Caldera stockpile plugin.
"""

import json
import yaml
import os
import re
import hashlib
import tempfile
import subprocess
import argparse
import datetime
from typing import Dict, List, Any, Optional


# More specific technique mappings for common tools and use cases
TOOL_SPECIFIC_TECHNIQUES = {
    "ioreg": {"attack_id": "T1082", "name": "System Information Discovery"},
    "sw_vers": {"attack_id": "T1082", "name": "System Information Discovery"},
    "dscl": {"attack_id": "T1087.001", "name": "Account Discovery: Local Account"},
    "osascript": {"attack_id": "T1059.002", "name": "Command and Scripting Interpreter: AppleScript"},
    "security": {"attack_id": "T1555.001", "name": "Credentials from Password Stores: Keychain"},
    "pbpaste": {"attack_id": "T1115", "name": "Clipboard Data"},
    "screencapture": {"attack_id": "T1113", "name": "Screen Capture"},
    "launchctl": {"attack_id": "T1543.001", "name": "Create or Modify System Process: Launch Agent"},
    "defaults": {"attack_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"},
    "mdfind": {"attack_id": "T1083", "name": "File and Directory Discovery"},
    "system_profiler": {"attack_id": "T1082", "name": "System Information Discovery"},
    "networksetup": {"attack_id": "T1016", "name": "System Network Configuration Discovery"},
    "sqlite3": {"attack_id": "T1005", "name": "Data from Local System"},
    "last": {"attack_id": "T1033", "name": "System Owner/User Discovery"},
    "sysctl": {"attack_id": "T1082", "name": "System Information Discovery"},
    "tmutil": {"attack_id": "T1490", "name": "Inhibit System Recovery"},
    "spctl": {"attack_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
    "csrutil": {"attack_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
    "hdiutil": {"attack_id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
    "xattr": {"attack_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
    "dns-sd": {"attack_id": "T1046", "name": "Network Service Scanning"},
    "nvram": {"attack_id": "T1082", "name": "System Information Discovery"},
    "mktemp": {"attack_id": "T1036", "name": "Masquerading"},
    "dsconfigad": {"attack_id": "T1016", "name": "System Network Configuration Discovery"},
    "swift": {"attack_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
    "tclsh": {"attack_id": "T1574.006", "name": "Hijack Execution Flow: Dynamic Linker Hijacking"},
    "ssh-keygen": {"attack_id": "T1574.006", "name": "Hijack Execution Flow: Dynamic Linker Hijacking"},
    "textutil": {"attack_id": "T1005", "name": "Data from Local System"},
    "say": {"attack_id": "T1005", "name": "Data from Local System"},
    "open": {"attack_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
    "scutil": {"attack_id": "T1016", "name": "System Network Configuration Discovery"},
    "safaridriver": {"attack_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
    "nscurl": {"attack_id": "T1105", "name": "Ingress Tool Transfer"},
    "log": {"attack_id": "T1070.002", "name": "Indicator Removal on Host: Clear Linux or Mac System Logs"},
    "profiles": {"attack_id": "T1082", "name": "System Information Discovery"},
    "mdls": {"attack_id": "T1083", "name": "File and Directory Discovery"},
    "sysadminctl": {"attack_id": "T1136.001", "name": "Create Account: Local Account"},
    "plutil": {"attack_id": "T1647", "name": "Plist File Modification"},
    "ditto": {"attack_id": "T1005", "name": "Data from Local System"},
    "codesign": {"attack_id": "T1553.002", "name": "Subvert Trust Controls: Code Signing"},
    "systemsetup": {"attack_id": "T1021.004", "name": "Remote Services: SSH"},
    "odutil": {"attack_id": "T1087.001", "name": "Account Discovery: Local Account"},
    "osacompile": {"attack_id": "T1059.002", "name": "Command and Scripting Interpreter: AppleScript"},
    "caffeinate": {"attack_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
    "GetFileInfo": {"attack_id": "T1083", "name": "File and Directory Discovery"},
    "SetFile": {"attack_id": "T1564.001", "name": "Hide Artifacts: Hidden Files and Directories"},
    "kextstat": {"attack_id": "T1082", "name": "System Information Discovery"},
    "sfltool": {"attack_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"},
    "lsregister": {"attack_id": "T1546.015", "name": "Event Triggered Execution: Component Object Model Hijacking"},
    "streamzip": {"attack_id": "T1560.001", "name": "Archive Collected Data: Archive via Utility"},
    "dsexport": {"attack_id": "T1087.002", "name": "Account Discovery: Domain Account"},
    "chflags": {"attack_id": "T1564.001", "name": "Hide Artifacts: Hidden Files and Directories"},
    "softwareupdate": {"attack_id": "T1082", "name": "System Information Discovery"},
    "dscacheutil": {"attack_id": "T1087.001", "name": "Account Discovery: Local Account"}
}

# Tactic-based technique mapping with more specific techniques
TACTIC_SPECIFIC_TECHNIQUES = {
    "discovery": [
        {"keywords": ["system", "info", "hardware", "software"], "attack_id": "T1082", "name": "System Information Discovery"},
        {"keywords": ["network", "wifi", "dns"], "attack_id": "T1016", "name": "System Network Configuration Discovery"},
        {"keywords": ["user", "account", "group"], "attack_id": "T1087.001", "name": "Account Discovery: Local Account"},
        {"keywords": ["file", "directory", "find"], "attack_id": "T1083", "name": "File and Directory Discovery"},
        {"keywords": ["process"], "attack_id": "T1057", "name": "Process Discovery"},
        {"keywords": ["peripheral", "usb", "device"], "attack_id": "T1120", "name": "Peripheral Device Discovery"},
        {"keywords": ["network", "connection"], "attack_id": "T1049", "name": "System Network Connections Discovery"},
        {"keywords": ["remote", "host"], "attack_id": "T1018", "name": "Remote System Discovery"},
        {"keywords": ["security", "antivirus", "av"], "attack_id": "T1518.001", "name": "Software Discovery: Security Software Discovery"},
        {"keywords": ["software", "application"], "attack_id": "T1518", "name": "Software Discovery"}
    ],
    "collection": [
        {"keywords": ["clipboard"], "attack_id": "T1115", "name": "Clipboard Data"},
        {"keywords": ["screen", "capture"], "attack_id": "T1113", "name": "Screen Capture"},
        {"keywords": ["archive", "compress", "zip"], "attack_id": "T1560.001", "name": "Archive Collected Data: Archive via Utility"},
        {"keywords": ["file", "data"], "attack_id": "T1005", "name": "Data from Local System"}
    ],
    "credential-access": [
        {"keywords": ["keychain", "password"], "attack_id": "T1555.001", "name": "Credentials from Password Stores: Keychain"},
        {"keywords": ["credential", "password"], "attack_id": "T1555", "name": "Credentials from Password Stores"}
    ],
    "defense-evasion": [
        {"keywords": ["gatekeeper", "quarantine", "xattr"], "attack_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
        {"keywords": ["hidden", "hide", "invisible"], "attack_id": "T1564.001", "name": "Hide Artifacts: Hidden Files and Directories"},
        {"keywords": ["codesign", "sign"], "attack_id": "T1553.002", "name": "Subvert Trust Controls: Code Signing"},
        {"keywords": ["decode", "decompress"], "attack_id": "T1140", "name": "Deobfuscate/Decode Files or Information"}
    ],
    "execution": [
        {"keywords": ["applescript", "osascript"], "attack_id": "T1059.002", "name": "Command and Scripting Interpreter: AppleScript"},
        {"keywords": ["shell", "command"], "attack_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"}
    ],
    "persistence": [
        {"keywords": ["launch", "agent", "daemon"], "attack_id": "T1543.001", "name": "Create or Modify System Process: Launch Agent"},
        {"keywords": ["startup", "login"], "attack_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"},
        {"keywords": ["account", "user", "create"], "attack_id": "T1136.001", "name": "Create Account: Local Account"}
    ],
    "exfiltration": [
        {"keywords": ["network", "transfer"], "attack_id": "T1041", "name": "Exfiltration Over C2 Channel"}
    ],
    "impact": [
        {"keywords": ["backup", "recovery"], "attack_id": "T1490", "name": "Inhibit System Recovery"},
        {"keywords": ["delete", "destroy"], "attack_id": "T1485", "name": "Data Destruction"}
    ],
    "lateral-movement": [
        {"keywords": ["ssh", "remote"], "attack_id": "T1021.004", "name": "Remote Services: SSH"}
    ],
    "command-and-control": [
        {"keywords": ["web", "http"], "attack_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
        {"keywords": ["download", "transfer"], "attack_id": "T1105", "name": "Ingress Tool Transfer"}
    ]
}


def normalize_tactic(tactic: str) -> str:
    """Normalize tactic name to match schema enum."""
    return tactic.lower().replace(" ", "-")


def get_technique_for_tactic(tactic: str, tool_name: str = None, use_case_text: str = "") -> Dict[str, str]:
    """Get MITRE technique info for a given tactic, tool, and use case context."""
    # First check for tool-specific technique
    if tool_name and tool_name in TOOL_SPECIFIC_TECHNIQUES:
        return TOOL_SPECIFIC_TECHNIQUES[tool_name]
    
    # Try to match based on tactic and keywords in use case
    normalized = normalize_tactic(tactic)
    if normalized in TACTIC_SPECIFIC_TECHNIQUES:
        use_case_lower = use_case_text.lower()
        for technique_mapping in TACTIC_SPECIFIC_TECHNIQUES[normalized]:
            keywords = technique_mapping["keywords"]
            if any(keyword in use_case_lower for keyword in keywords):
                return {
                    "attack_id": technique_mapping["attack_id"],
                    "name": technique_mapping["name"]
                }
        
        # If no keyword match, use the first technique for this tactic
        first_technique = TACTIC_SPECIFIC_TECHNIQUES[normalized][0]
        return {
            "attack_id": first_technique["attack_id"],
            "name": first_technique["name"]
        }
    
    # Final fallback based on the old TACTIC_TECHNIQUE_MAP
    tactic_fallbacks = {
        "discovery": {"attack_id": "T1082", "name": "System Information Discovery"},
        "collection": {"attack_id": "T1005", "name": "Data from Local System"},
        "credential-access": {"attack_id": "T1555", "name": "Credentials from Password Stores"},
        "defense-evasion": {"attack_id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
        "execution": {"attack_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
        "exfiltration": {"attack_id": "T1041", "name": "Exfiltration Over C2 Channel"},
        "impact": {"attack_id": "T1485", "name": "Data Destruction"},
        "initial-access": {"attack_id": "T1190", "name": "Exploit Public-Facing Application"},
        "lateral-movement": {"attack_id": "T1021.004", "name": "Remote Services: SSH"},
        "persistence": {"attack_id": "T1543.001", "name": "Create or Modify System Process: Launch Agent"},
        "privilege-escalation": {"attack_id": "T1068", "name": "Exploitation for Privilege Escalation"},
        "command-and-control": {"attack_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
        "reconnaissance": {"attack_id": "T1592", "name": "Gather Victim Host Information"}
    }
    
    return tactic_fallbacks.get(normalized, {
        "attack_id": "T1059.004", 
        "name": "Command and Scripting Interpreter: Unix Shell"
    })


def clean_command(command: str) -> str:
    """Clean and format command for YAML output."""
    command = command.strip()
    if '\n' in command:
        command = command.replace('\r\n', '\n').replace('\r', '\n')
    return command


def sanitize_filename(name: str) -> str:
    """Sanitize tool name for use as filename."""
    sanitized = re.sub(r'[^\w\-_.]', '_', name)
    sanitized = re.sub(r'_+', '_', sanitized)
    return sanitized.lower()


def get_required_privilege(tool_name: str, command: str) -> str:
    """Determine required privilege level based on tool and command."""
    
    # Tools that typically require elevated privileges
    elevated_tools = {
        "spctl", "csrutil", "systemsetup", "sysadminctl", "tmutil", 
        "defaults", "launchctl", "security", "log"
    }
    
    # Check if tool typically requires elevation
    if tool_name in elevated_tools:
        return "Elevated"
    
    # Check command content for sudo or privilege indicators
    command_lower = command.lower()
    if any(indicator in command_lower for indicator in ["sudo", "/library/", "system.keychain"]):
        return "Elevated"
    
    # Default to User level
    return "User"


def should_be_singleton(tool_name: str, use_case_name: str, tactic: str) -> bool:
    """Determine if procedure should be singleton based on tool and use case."""
    
    # Some operations should only run once
    singleton_indicators = [
        "disable", "enable", "create account", "delete", "install", 
        "uninstall", "modify", "reset", "configure"
    ]
    
    use_case_lower = use_case_name.lower()
    if any(indicator in use_case_lower for indicator in singleton_indicators):
        return True
    
    # Impact operations typically should be singleton
    if tactic == "impact":
        return True
        
    return False


def generate_deterministic_uuid(content: str) -> str:
    """Generate a deterministic UUID based on content hash"""
    # Create MD5 hash of the content for deterministic UUID
    hash_obj = hashlib.md5(content.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Format as proper UUID: 8-4-4-4-12
    return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"


def create_procedure_from_use_case(tool: Dict[str, Any], use_case: Dict[str, Any], verbose: bool = False, force: bool = False, output_dir: str = "") -> Optional[Dict[str, Any]]:
    """Create a single procedure from a tool and use case."""
    
    # Check for existing GUID in LOOBins data (preserve if exists)
    existing_guid = tool.get('id') or use_case.get('id')
    
    if existing_guid:
        procedure_id = existing_guid
        if verbose:
            print(f"    Using existing GUID: {procedure_id}")
    else:
        # Generate deterministic UUID based on tool name and use case
        uuid_content = f"{tool.get('name', '')}_{use_case.get('name', '')}_{use_case.get('code', '')}"
        procedure_id = generate_deterministic_uuid(uuid_content)
        if verbose:
            print(f"    Generated GUID: {procedure_id}")
    
    # Check if file already exists (GUID preservation)
    tactic = normalize_tactic(use_case.get("tactics", ["Discovery"])[0])
    expected_file = os.path.join(output_dir, tactic, f"{procedure_id}.yml")
    
    if os.path.exists(expected_file) and not force:
        if verbose:
            print(f"    SKIPPED: File exists (use --force to overwrite)")
        return None
    
    tactics = use_case.get("tactics", ["Discovery"])
    primary_tactic = normalize_tactic(tactics[0])
    
    tool_name = tool.get("name", "")
    use_case_text = f"{use_case.get('name', '')} {use_case.get('description', '')} {use_case.get('code', '')}"
    technique = get_technique_for_tactic(primary_tactic, tool_name, use_case_text)
    
    procedure_name = f"{tool['name']} - {use_case['name']}"
    
    command = clean_command(use_case["code"])
    
    # Build the procedure with required fields
    procedure = {
        "id": procedure_id,
        "name": procedure_name,
        "description": use_case["description"],
        "tactic": primary_tactic,
        "technique": technique,
        "platforms": {
            "darwin": {
                "sh": {
                    "command": command
                }
            }
        }
    }
    
    # Add Caldera ability defaults (consistent with other scripts)
    procedure["singleton"] = should_be_singleton(tool_name, use_case.get('name', ''), primary_tactic)
    procedure["privilege"] = get_required_privilege(tool_name, command)
    procedure["repeatable"] = not procedure["singleton"]  # If singleton, not repeatable
    procedure["delete_payload"] = False  # Remove or leave  payloads after execution
    
    # Add buckets for categorization - use tool name and tactic
    procedure["buckets"] = ['loobins', tool_name.lower(), primary_tactic]
    
    # Add metadata fields (consistent with other scripts)
    procedure["version"] = "1.0"
    procedure["author"] = "LOOBins Project"
    
    # Add additional metadata in additional_info
    additional_info = {
        "loobins_tool": tool_name,
        "use_case": use_case.get('name', ''),
        "source_file": f"{tool_name}.yml",
        "source_repository": "https://github.com/infosecB/LOOBins",
        "import_timestamp": datetime.datetime.utcnow().isoformat() + 'Z'
    }
    

    
    # Add any extra metadata from tool or use case
    if 'description' in tool and tool['description'] != procedure['description']:
        additional_info['tool_description'] = tool['description']
    
    if 'category' in tool:
        additional_info['category'] = tool['category']
    
    if 'tags' in tool:
        additional_info['tags'] = tool['tags']
        
    if 'references' in tool:
        additional_info['references'] = tool['references']
        
    if additional_info:
        procedure["additional_info"] = additional_info
    
    return procedure


def save_procedure_to_tactic(procedure: Dict[str, Any], base_output_dir: str, verbose: bool = False, force: bool = False) -> bool:
    """Save procedure to tactic-specific directory (copied from atomic script pattern)"""
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


def convert_loobins_to_caldera(repo_url: str, output_dir: str, limit: Optional[int] = None, verbose: bool = False, force: bool = False) -> bool:
    """Main conversion function."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Clone the LOOBins repository
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
        repo_dir = os.path.join(temp_dir, "loobins")
        
        if verbose:
            print(f"Cloning LOOBins repository from {repo_url}...")
        else:
            print(f"Cloning LOOBins repository...")
            
        try:
            subprocess.run(['git', 'clone', '--depth=1', repo_url, repo_dir], 
                         check=True, env=env, capture_output=True, text=True)
            
            # Look for YAML files in the LOOBins directory
            loobins_dir = os.path.join(repo_dir, "LOOBins")
            if not os.path.exists(loobins_dir):
                raise FileNotFoundError(f"LOOBins directory not found in repository")
            
            # Get all YAML files
            yaml_files = [f for f in os.listdir(loobins_dir) if f.endswith('.yml') or f.endswith('.yaml')]
            
            if limit:
                yaml_files = yaml_files[:limit]
                if verbose:
                    print(f"Processing first {limit} tools only")
            
            # Convert YAML files to our expected format
            loobins_data = []
            for yaml_file in yaml_files:
                tool_file = os.path.join(loobins_dir, yaml_file)
                with open(tool_file, 'r') as f:
                    tool_data = yaml.safe_load(f)
                    if tool_data:
                        loobins_data.append(tool_data)
                        
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to clone LOOBins repository: {e}")
            print(f"       stderr: {e.stderr}")
            return False
        except Exception as e:
            print(f"ERROR: Failed to process LOOBins repository: {e}")
            return False
    
        print(f"Processing {len(loobins_data)} tools from LOOBins repository")
        if verbose:
            print(f"Output directory: {output_dir}")
        
        total_procedures = 0
        skipped_existing = 0
        
        for i, tool in enumerate(loobins_data):
            tool_name = tool.get("name", f"unknown_tool_{i}")
            if verbose:
                print(f"\nProcessing tool: {tool_name}")
            else:
                print(f"Processing {tool_name}...")
            
            use_cases = tool.get("example_use_cases", [])
            if not use_cases:
                if verbose:
                    print(f"  Warning: No use cases found for {tool_name}")
                continue
            
            for use_case_idx, use_case in enumerate(use_cases):
                try:
                    procedure = create_procedure_from_use_case(tool, use_case, verbose, force, output_dir)
                    if procedure:
                        if save_procedure_to_tactic(procedure, output_dir, verbose, force):
                            total_procedures += 1
                        else:
                            skipped_existing += 1
                except Exception as e:
                    if verbose:
                        print(f"  Error creating procedure for {tool_name} use case {use_case_idx}: {e}")
                    continue
        
        print(f"\nSUCCESS: Created {total_procedures} LOOBins procedures")
        if skipped_existing > 0:
            print(f"WARNING: Skipped {skipped_existing} existing procedures (use --force to overwrite)")
        if verbose:
            print(f"Output directory: {output_dir}")
        
        return True


def parse_arguments():
    """Parse command line arguments"""
    
    parser = argparse.ArgumentParser(
        description="Convert LOOBins repository to Caldera procedure files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
          %(prog)s --output ../abilities/darwin/   # Clone repo and output to darwin
  %(prog)s --verbose --force                # Verbose mode, overwrite existing
  %(prog)s --limit 10                       # Process only first 10 tools
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
        default="https://github.com/infosecB/LOOBins.git",
        help='LOOBins repository URL (default: official repo)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of tools to process (for testing)'
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
        print(f"LOOBins repository: {args.repo_url}")
        print(f"Output directory: {args.output}")
        if args.limit:
            print(f"Processing limit: {args.limit} tools")
        if args.force:
            print("Force mode: Will overwrite existing files")
    
    # Convert LOOBins data
    success = convert_loobins_to_caldera(args.repo_url, args.output, args.limit, args.verbose, args.force)
    
    if success:
        print("Conversion completed successfully!")
        return 0
    else:
        print("Conversion failed!")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main()) 