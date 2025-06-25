#!/usr/bin/env python3
"""
Configuration settings for CI/CD pipeline.
"""

import os
from pathlib import Path

# Detect if running in CI environment
IS_CI = os.getenv('CI', 'false').lower() == 'true'
IS_GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'

# Base paths
PROJECT_ROOT = Path(__file__).parent.parent
CICD_DIR = Path(__file__).parent

# Output directories
WINDOWS_OUTPUT = PROJECT_ROOT / "windows"
DARWIN_OUTPUT = PROJECT_ROOT / "darwin" 
LINUX_OUTPUT = PROJECT_ROOT / "linux"

# Default MITRE ATT&CK STIX file locations to try
STIX_LOCATIONS = [
    PROJECT_ROOT / "cti" / "enterprise-attack.json",
    CICD_DIR / "enterprise-attack.json",
    Path.home() / ".mitre" / "enterprise-attack.json"
]

# CI-specific configurations
CI_CONFIG = {
    'timeout_seconds': 300,  # 5 minutes max per script
    'max_retries': 3,
    'rate_limit_delay': 1,  # seconds between API calls
    'chunk_size': 100,  # process in chunks to avoid timeouts
}

# External data sources
DATA_SOURCES = {
    'lolbas_api': 'https://lolbas-project.github.io/api/lolbas.json',
    'loldrivers_yaml_api': 'https://api.github.com/repos/magicsword-io/LOLDrivers/contents/yaml',
    'loldrivers_drivers_api': 'https://api.github.com/repos/magicsword-io/LOLDrivers/contents/drivers',
    'loobins_json': 'https://github.com/infosecB/LOOBins/raw/main/LOOBins.json',
    'mitre_stix': 'https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json'
}

def ensure_output_dirs():
    """Ensure all output directories exist"""
    for output_dir in [WINDOWS_OUTPUT, DARWIN_OUTPUT, LINUX_OUTPUT]:
        output_dir.mkdir(parents=True, exist_ok=True)

def get_mitre_stix_path():
    """Get the best available MITRE STIX file path"""
    for stix_path in STIX_LOCATIONS:
        if stix_path.exists():
            return stix_path
    return None

def download_mitre_stix():
    """Download MITRE STIX file if not available locally"""
    import requests
    
    stix_path = CICD_DIR / "enterprise-attack.json"
    if stix_path.exists():
        return stix_path
        
    try:
        print(f"Downloading MITRE ATT&CK STIX data to {stix_path}...")
        response = requests.get(DATA_SOURCES['mitre_stix'], timeout=60)
        response.raise_for_status()
        
        with open(stix_path, 'w') as f:
            f.write(response.text)
            
        print(f"✅ MITRE STIX data downloaded successfully")
        return stix_path
        
    except Exception as e:
        print(f"❌ Failed to download MITRE STIX data: {e}")
        return None 