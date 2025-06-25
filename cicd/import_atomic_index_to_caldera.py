#!/usr/bin/env python3
"""
Import Atomic Red Team index files to Caldera procedure library.
Clean, modular implementation with proper separation of concerns.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Iterator, Union

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install PyYAML")
    sys.exit(1)

# Configuration
CALDERA_ROOT = Path(__file__).parent.parent
DEFAULT_WINDOWS_PATH = CALDERA_ROOT / "abilities" / "windows"
DEFAULT_DARWIN_PATH = CALDERA_ROOT / "abilities" / "darwin"
DEFAULT_LINUX_PATH = CALDERA_ROOT / "abilities" / "linux"

# Public URLs for atomic index files
ATOMIC_INDEX_URLS = {
    'macos': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/macos-index.yaml',
    'windows': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/windows-index.yaml',
    'linux': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/linux-index.yaml'
}

# Platform mappings
PLATFORM_MAP = {'windows': 'windows', 'macos': 'darwin', 'linux': 'linux'}
EXECUTOR_MAP = {'powershell': 'psh', 'sh': 'sh', 'cmd': 'cmd'}

# Atomic Red Team repository for payload cloning
ATOMIC_REPO_URL = 'https://github.com/redcanaryco/atomic-red-team.git'


class Platform(Enum):
    """Platform enumeration with proper mapping."""
    MACOS = 'macos'
    WINDOWS = 'windows' 
    LINUX = 'linux'
    
    @property
    def target_platform(self) -> str:
        """Get the target platform mapping."""
        mapping = {
            Platform.MACOS: 'darwin',
            Platform.WINDOWS: 'windows',
            Platform.LINUX: 'linux'
        }
        return mapping[self]


class Executor(Enum):
    """Executor type enumeration."""
    POWERSHELL = 'powershell'
    BASH = 'sh'
    CMD = 'cmd'
    
    @property
    def caldera_name(self) -> str:
        """Get the Caldera executor name."""
        mapping = {
            Executor.POWERSHELL: 'psh',
            Executor.BASH: 'sh', 
            Executor.CMD: 'cmd'
        }
        return mapping[self]


@dataclass
class ConversionStats:
    """Statistics for conversion process."""
    processed: int = 0
    created: int = 0
    skipped: int = 0
    errors: int = 0
    
    def __iadd__(self, other: 'ConversionStats') -> 'ConversionStats':
        """Add another stats object to this one."""
        self.processed += other.processed
        self.created += other.created
        self.skipped += other.skipped
        self.errors += other.errors
        return self
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary for compatibility."""
        return {
            'processed': self.processed,
            'created': self.created,
            'skipped': self.skipped,
            'errors': self.errors
        }


@dataclass
class AtomicTest:
    """Represents an atomic test with its metadata."""
    guid: str
    name: str
    description: str
    executor: Dict[str, Any] = field(default_factory=dict)
    input_arguments: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    author: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional['AtomicTest']:
        """Create AtomicTest from dictionary data."""
        guid = data.get('auto_generated_guid')
        if not guid:
            return None
            
        return cls(
            guid=guid,
            name=data.get('name', 'Unknown Test'),
            description=data.get('description', '').strip(),
            executor=data.get('executor', {}),
            input_arguments=data.get('input_arguments', {}),
            dependencies=data.get('dependencies', []),
            tags=data.get('tags', []),
            author=data.get('author')
        )


class RepoManager:
    """Manages atomic-red-team repository cloning and cleanup"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.temp_dir: Optional[Path] = None
        self.repo_path: Optional[Path] = None
        self.logger = logging.getLogger(__name__)
    
    @contextmanager
    def get_repo(self) -> Iterator[Path]:
        """Context manager for atomic repo access"""
        try:
            self._clone_repo()
            yield self.repo_path
        finally:
            self._cleanup()
    
    def _clone_repo(self) -> None:
        """Clone atomic-red-team repository"""
        if self.verbose:
            self.logger.info("Cloning atomic-red-team repository...")
        
        self.temp_dir = Path(tempfile.mkdtemp())
        self.repo_path = self.temp_dir / 'atomic-red-team'
        
        env = self._get_proxy_bypass_env()
        
        for branch in ['master', 'main']:
            try:
                result = subprocess.run([
                    'git', 'clone', '--depth=1', '--branch', branch, 
                    ATOMIC_REPO_URL, str(self.repo_path)
                ], capture_output=True, text=True, timeout=120, env=env, check=False)
                
                if result.returncode == 0:
                    if self.verbose:
                        self.logger.info(f"Successfully cloned ({branch} branch)")
                    return
                    
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue
        
        raise RuntimeError("Failed to clone atomic-red-team repository")
    
    def _cleanup(self) -> None:
        """Clean up temporary directory"""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @staticmethod
    def _get_proxy_bypass_env() -> Dict[str, str]:
        """Get environment with proxy bypass"""
        env = os.environ.copy()
        env.update({
            'NO_PROXY': '*', 'no_proxy': '*',
            'HTTP_PROXY': '', 'HTTPS_PROXY': '',
            'http_proxy': '', 'https_proxy': ''
        })
        return env


class PayloadManager:
    """Manages payload copying from atomic repo"""
    
    def __init__(self, payloads_dir: Optional[Path], repo_path: Optional[Path], verbose: bool = False):
        self.payloads_dir = payloads_dir
        self.repo_path = repo_path
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self._payloads_copied = False
    
    def copy_all_payloads(self) -> int:
        """Copy all payload files from atomic repo to payloads directory"""
        if not all([self.payloads_dir, self.repo_path]) or self._payloads_copied:
            return 0
        
        atomics_dir = self.repo_path / 'atomics'
        external_payloads_dir = self.repo_path / 'ExternalPayloads'
        
        if not atomics_dir.exists():
            return 0
        
        self.payloads_dir.mkdir(parents=True, exist_ok=True)
        copied_count = 0
        
        # Copy from atomics directory
        copied_count += self._copy_from_directory(atomics_dir)
        
        # Copy from external payloads if it exists
        if external_payloads_dir.exists():
            copied_count += self._copy_from_directory(external_payloads_dir)
        
        self._payloads_copied = True
        
        if self.verbose and copied_count > 0:
            self.logger.info(f"Copied {copied_count} payload files total")
        
        return copied_count
    
    def _copy_from_directory(self, source_dir: Path) -> int:
        """Copy all payload files from a source directory"""
        copied_count = 0
        
        # Common payload file extensions
        payload_extensions = {
            '.exe', '.dll', '.bat', '.ps1', '.sh', '.py', '.c', '.cpp', '.cc', '.h',
            '.js', '.vbs', '.jar', '.zip', '.msi', '.reg', '.xml', '.txt', '.csv',
            '.plist', '.swift', '.m', '.go', '.rs', '.osa', '.scpt', '.mof',
            '.iso', '.cab', '.conf', '.xsl', '.json'
        }
        
        try:
            for file_path in source_dir.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in payload_extensions:
                    # Skip very large files (> 10MB) that are likely not payloads
                    if file_path.stat().st_size > 10 * 1024 * 1024:
                        continue
                    
                    dst_file = self.payloads_dir / file_path.name
                    
                    # Only copy if destination doesn't exist
                    if not dst_file.exists():
                        try:
                            import shutil
                            shutil.copy2(file_path, dst_file)
                            copied_count += 1
                            
                            if self.verbose:
                                self.logger.info(f"Copied payload: {file_path.name}")
                                
                        except Exception as e:
                            if self.verbose:
                                self.logger.error(f"Error copying {file_path.name}: {e}")
                            
        except Exception as e:
            if self.verbose:
                self.logger.error(f"Error scanning directory {source_dir}: {e}")
        
        return copied_count


class IndexFetcher:
    """Fetches atomic index files from URLs or local paths"""
    
    @staticmethod
    def fetch(source: str, verbose: bool = False) -> str:
        """Fetch index content from URL or file"""
        if source.startswith('http'):
            return IndexFetcher._fetch_from_url(source, verbose)
        else:
            return IndexFetcher._fetch_from_file(source, verbose)
    
    @staticmethod
    def _fetch_from_url(url: str, verbose: bool) -> str:
        """Fetch from URL using git clone approach"""
        logger = logging.getLogger(__name__)
        if verbose:
            logger.info(f"Fetching from URL: {url}")
        
        if 'raw.githubusercontent.com' not in url:
            raise ValueError(f"Unsupported URL format: {url}")
        
        # Parse GitHub URL
        parts = url.replace('https://raw.githubusercontent.com/', '').split('/')
        if len(parts) < 4:
            raise ValueError(f"Invalid GitHub URL format: {url}")
        
        owner, repo, branch = parts[0], parts[1], parts[2]
        file_path = '/'.join(parts[3:])
        repo_url = f"https://github.com/{owner}/{repo}.git"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_repo = Path(temp_dir) / 'temp_repo'
            env = RepoManager._get_proxy_bypass_env()
            
            result = subprocess.run([
                'git', 'clone', '--depth=1', '--branch', branch, 
                repo_url, str(temp_repo)
            ], capture_output=True, text=True, timeout=120, env=env, check=False)
            
            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")
            
            target_file = temp_repo / file_path
            if not target_file.exists():
                raise FileNotFoundError(f"File {file_path} not found in repository")
            
            return target_file.read_text(encoding='utf-8')
    
    @staticmethod
    def _fetch_from_file(file_path: str, verbose: bool) -> str:
        """Fetch from local file"""
        logger = logging.getLogger(__name__)
        if verbose:
            logger.info(f"Reading local file: {file_path}")
        
        try:
            return Path(file_path).read_text(encoding='utf-8')
        except FileNotFoundError:
            raise FileNotFoundError(f"Local file not found: {file_path}")


class ProcedureBuilder:
    """Builds Caldera procedures from atomic tests"""
    
    @staticmethod
    def build_procedure(test: AtomicTest, technique_id: str, technique_name: str, 
                       tactic: str, technique_metadata: Dict[str, Any], target_platform: str) -> Optional[Dict[str, Any]]:
        """Build a Caldera procedure from atomic test data"""
        
        # Build base procedure
        procedure = {
            'id': test.guid,
            'name': test.name,
            'description': test.description,
            'tactic': tactic,
            'technique': {'attack_id': technique_id, 'name': technique_name},
            'platforms': {},
            'plugin': 'atomic',
            'singleton': False,
            'repeatable': True,
            'delete_payload': False,
            'privilege': '',
            'buckets': ProcedureBuilder._build_buckets(technique_id, tactic, test)
        }
        
        # Add metadata
        procedure.update(ProcedureBuilder._build_metadata(test, technique_metadata))
        
        # Add platform executor
        executor_data = ProcedureBuilder._build_executor(test, target_platform)
        if executor_data:
            executor_name, platform_data = executor_data
            procedure['platforms'][target_platform] = {executor_name: platform_data}
        
        return procedure if procedure['platforms'] else None
    
    @staticmethod
    def _build_buckets(technique_id: str, tactic: str, test: AtomicTest) -> List[str]:
        """Build procedure buckets/tags"""
        buckets = ['atomic-red-team', technique_id.lower(), tactic.lower()]
        
        if test.tags:
            buckets.extend([tag.lower() for tag in test.tags])
        
        return list(set(buckets))  # Remove duplicates
    
    @staticmethod
    def _build_metadata(test: AtomicTest, technique_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Build procedure metadata fields"""
        metadata = {
            'author': test.author or 'Atomic Red Team'
        }
        
        # Additional info
        additional_info = {}
        
        # Add test data if present
        test_data = {
            'tags': test.tags,
            'input_arguments': test.input_arguments,
            'dependencies': test.dependencies
        }
        
        for field, value in test_data.items():
            if value:
                additional_info[field] = value
        
        # Add technique metadata
        additional_info.update(technique_metadata)
        
        # Add import metadata
        additional_info.update({
            'atomic_guid': test.guid,
            'import_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        })
        
        if additional_info:
            metadata['additional_info'] = additional_info
        
        return metadata
    
    @staticmethod
    def _build_executor(test: AtomicTest, target_platform: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Build executor data for procedure"""
        if not isinstance(test.executor, dict):
            return None
        
        command = test.executor.get('command', '')
        if not command:
            return None
        
        # Map executor name
        executor_name = test.executor.get('name', 'sh')
        try:
            executor_enum = Executor(executor_name)
            caldera_executor = executor_enum.caldera_name
        except ValueError:
            caldera_executor = 'sh'  # Default fallback
        
        # Process command with dependencies and input arguments
        final_command = CommandProcessor.process_command(test, command)
        
        # Build platform data
        platform_data = {'command': final_command}
        
        # Add cleanup if present
        cleanup = test.executor.get('cleanup_command', '')
        if cleanup:
            platform_data['cleanup'] = CommandProcessor.process_multiline(cleanup)
        
        # Add executor metadata
        for field in ['elevation_required', 'command_type']:
            if field in test.executor:
                platform_data[field] = test.executor[field]
        
        return caldera_executor, platform_data


class CommandProcessor:
    """Processes atomic test commands and dependencies"""
    
    @staticmethod
    def process_command(test: AtomicTest, command: str) -> str:
        """Process command with dependencies and input arguments"""
        # Handle dependencies
        dep_commands = []
        
        if isinstance(test.dependencies, list):
            for dep in test.dependencies:
                if not isinstance(dep, dict):
                    continue
                
                prereq = dep.get('prereq_command', '').strip()
                get_prereq = dep.get('get_prereq_command', '').strip()
                
                if prereq and get_prereq and 'exit 0' in prereq and 'exit 1' in prereq:
                    condition = prereq.split(';')[0].strip()
                    merged_dep = f"{condition}; then : ; else {get_prereq}; fi"
                    dep_commands.append(merged_dep)
        
        # Merge with main command
        all_commands = dep_commands + [command]
        full_command = '; '.join(all_commands)
        
        # Process input arguments
        if isinstance(test.input_arguments, dict):
            for arg_name, arg_data in test.input_arguments.items():
                if isinstance(arg_data, dict):
                    default_value = arg_data.get('default', '')
                    if default_value:
                        if 'PathToAtomicsFolder' in str(default_value):
                            filename = Path(str(default_value)).name
                            full_command = full_command.replace(f"#{{{arg_name}}}", filename)
                        else:
                            full_command = full_command.replace(f"#{{{arg_name}}}", str(default_value))
        
        return CommandProcessor.process_multiline(full_command)
    
    @staticmethod
    def process_multiline(command: str) -> str:
        """Convert multiline commands to single line"""
        if not command:
            return ''
        
        lines = [line.strip() for line in command.split('\n') if line.strip()]
        return '; '.join(lines)


class ProcedureSaver:
    """Saves procedures to tactic-specific directories"""
    
    @staticmethod
    def save_procedure(procedure: Dict[str, Any], output_dirs: Dict[str, Path], 
                      tactic: str, force: bool = False, verbose: bool = False) -> bool:
        """Save procedure to appropriate tactic directory"""
        saved = False
        logger = logging.getLogger(__name__)
        
        for platform in procedure['platforms']:
            if platform in output_dirs:
                if ProcedureSaver._save_to_platform(procedure, output_dirs[platform], 
                                                  tactic, force, verbose, logger):
                    saved = True
        
        return saved
    
    @staticmethod
    def _save_to_platform(procedure: Dict[str, Any], output_dir: Path, tactic: str, 
                         force: bool, verbose: bool, logger: logging.Logger) -> bool:
        """Save procedure to specific platform directory"""
        tactic_dir = output_dir / tactic
        tactic_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = tactic_dir / f"{procedure['id']}.yml"
        
        if output_file.exists() and not force:
            if verbose:
                logger.info(f"Skipped: {output_file} (use --force to overwrite)")
            return False
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump([procedure], f, default_flow_style=False, sort_keys=False)
            if verbose:
                logger.info(f"Saved: {output_file}")
            return True
        except Exception as e:
            if verbose:
                logger.error(f"Error saving {procedure['id']}: {e}")
            return False


class AtomicIndexConverter:
    """Main converter class - coordinates all the components"""
    
    def __init__(self, verbose: bool = False, force: bool = False, payloads_dir: Optional[Path] = None):
        self.verbose = verbose
        self.force = force
        self.payloads_dir = payloads_dir
        self.logger = self._setup_logger(verbose)
        
    def _setup_logger(self, verbose: bool) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:  # Avoid duplicate handlers
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        logger.setLevel(logging.INFO if verbose else logging.WARNING)
        return logger
        
    def convert_single_platform(self, platform: Platform, output_dirs: Dict[str, Path]) -> ConversionStats:
        """Convert single platform atomic index"""
        target_platform = platform.target_platform
        index_source = ATOMIC_INDEX_URLS[platform.value]
        
        print(f"Processing {platform.value} -> {target_platform}")
        print(f"   Source: {index_source}")
        
        if self.payloads_dir:
            with RepoManager(self.verbose).get_repo() as repo_path:
                return self._process_platform(index_source, target_platform, output_dirs, repo_path)
        else:
            return self._process_platform(index_source, target_platform, output_dirs, None)
    
    def convert_all_platforms(self, output_dirs: Dict[str, Path]) -> ConversionStats:
        """Convert all platforms with single repository clone"""
        combined_stats = ConversionStats()
        
        print("Processing all platforms with single repository clone")
        print("=" * 60)
        
        if self.payloads_dir:
            print("Cloning atomic-red-team repository for payloads...")
            with RepoManager(self.verbose).get_repo() as repo_path:
                print("  Repository ready for all platforms")
                combined_stats = self._process_all_platforms(output_dirs, repo_path)
        else:
            combined_stats = self._process_all_platforms(output_dirs, None)
        
        self._print_combined_results(combined_stats)
        return combined_stats
    
    def _process_all_platforms(self, output_dirs: Dict[str, Path], repo_path: Optional[Path]) -> ConversionStats:
        """Process all platforms with optional shared repo"""
        combined_stats = ConversionStats()
        
        for platform in Platform:
            target_platform = platform.target_platform
            print(f"\nProcessing {platform.value} -> {target_platform}")
            print(f"   Source: {ATOMIC_INDEX_URLS[platform.value]}")
            
            try:
                platform_stats = self._process_platform(
                    ATOMIC_INDEX_URLS[platform.value], target_platform, output_dirs, repo_path
                )
                
                combined_stats += platform_stats
                print(f"   Completed: {platform_stats.created} created, {platform_stats.skipped} skipped")
                
            except Exception as e:
                print(f"   Failed: {e}")
                combined_stats.errors += 1
        
        return combined_stats
    
    def _process_platform(self, index_source: str, target_platform: str, 
                         output_dirs: Dict[str, Path], repo_path: Optional[Path]) -> ConversionStats:
        """Process a single platform index"""
        platform_stats = ConversionStats()
        
        # Get index content
        content = IndexFetcher.fetch(index_source, self.verbose)
        data = yaml.safe_load(content)
        
        # Setup payload manager and copy all payloads once
        payload_manager = PayloadManager(self.payloads_dir, repo_path, self.verbose)
        if self.payloads_dir and repo_path:
            payload_count = payload_manager.copy_all_payloads()
            if payload_count > 0:
                print(f"   Copied {payload_count} payload files")
        
        # Process each tactic/technique
        for tactic, techniques in data.items():
            if not isinstance(techniques, dict):
                continue
            
            for technique_id, technique_data in techniques.items():
                stats = self._process_technique(
                    technique_id, technique_data, tactic, target_platform, output_dirs
                )
                platform_stats += stats
        
        return platform_stats
    
    def _process_technique(self, technique_id: str, technique_data: Dict[str, Any], tactic: str,
                          target_platform: str, output_dirs: Dict[str, Path]) -> ConversionStats:
        """Process a single technique"""
        stats = ConversionStats()
        
        if not isinstance(technique_data, dict) or 'atomic_tests' not in technique_data:
            return stats
        
        technique_name = technique_data.get('technique', {}).get('name', technique_id)
        
        # Extract technique metadata
        technique_metadata = {}
        if 'technique' in technique_data and isinstance(technique_data['technique'], dict):
            tech_info = technique_data['technique']
            for field in ['created', 'updated', 'version', 'references', 'tags']:
                if field in tech_info:
                    technique_metadata[f'technique_{field}'] = tech_info[field]
        
        atomic_tests = technique_data.get('atomic_tests', [])
        if not isinstance(atomic_tests, list):
            return stats
        
        # Process each atomic test
        for test_data in atomic_tests:
            if not isinstance(test_data, dict):
                continue
            
            stats.processed += 1
            
            # Create AtomicTest object
            test = AtomicTest.from_dict(test_data)
            if not test:
                stats.skipped += 1
                continue
            
            # Build procedure (no need to extract/copy payloads - they're all copied already)
            procedure = ProcedureBuilder.build_procedure(
                test, technique_id, technique_name, tactic, 
                technique_metadata, target_platform
            )
            
            if procedure:
                if ProcedureSaver.save_procedure(procedure, output_dirs, tactic, self.force, self.verbose):
                    stats.created += 1
                else:
                    stats.skipped += 1
            else:
                stats.skipped += 1
        
        return stats
    
    def _print_combined_results(self, stats: ConversionStats) -> None:
        """Print combined results summary"""
        print("\n" + "=" * 60)
        print("  COMBINED RESULTS:")
        print(f"   Processed: {stats.processed}")
        print(f"   Created: {stats.created}")
        print(f"   Skipped: {stats.skipped}")
        print(f"   Errors: {stats.errors}")


def setup_logging(verbose: bool) -> None:
    """Setup global logging configuration."""
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s',
        force=True  # Override any existing logging config
    )


def validate_urls() -> None:
    """Validate all official atomic index URLs."""
    print("Validating official atomic index URLs...")
    for platform_name, url in ATOMIC_INDEX_URLS.items():
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36')
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.getcode() == 200:
                    print(f"  SUCCESS {platform_name}: {url}")
                else:
                    print(f"  FAILED {platform_name}: {url} (HTTP {response.getcode()})")
        except Exception as e:
            print(f"  FAILED {platform_name}: {url} ({e})")


def print_available_platforms() -> None:
    """Print available official atomic index platforms."""
    print("Available official atomic index platforms:")
    for platform_name, url in ATOMIC_INDEX_URLS.items():
        print(f"  - {platform_name}: {url}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Convert Atomic Red Team index to Caldera procedures",
        epilog="""
Examples:
  # Process ALL platforms with single repository clone (recommended for CI/CD)
  python3 %(prog)s --all-platforms --payloads-dir ../payloads/ --force

  # Convert single platform: macOS atomic tests (auto-maps macos → darwin)
  python3 %(prog)s --platform macos --force

  # Convert single platform: Windows tests (auto-maps windows → windows)  
  python3 %(prog)s --platform windows --force

  # Convert from custom URL (requires explicit target platform)
  python3 %(prog)s --index-url https://example.com/index.yaml --target-platform darwin

  # Convert local file (requires explicit target platform)
  python3 %(prog)s --index-file ./local-index.yaml --target-platform windows

  # Override auto-mapping (advanced usage)
  python3 %(prog)s --platform macos --target-platform linux --force

  # List available official platforms
  python3 %(prog)s --list-platforms

  # Validate URLs before automation
  python3 %(prog)s --validate-urls
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input source options
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument('--index-file', type=str, help='Path to local atomic index YAML file')
    input_group.add_argument('--index-url', type=str, help='URL to atomic index YAML file')
    input_group.add_argument('--platform', choices=[p.value for p in Platform], 
                           help='Fetch official atomic index for specified platform')
    input_group.add_argument('--all-platforms', action='store_true',
                           help='Process all official platforms (macos, windows, linux) with single repo clone')
    
    # Utility options
    parser.add_argument('--list-platforms', action='store_true',
                       help='List available official platform indexes and exit')
    parser.add_argument('--validate-urls', action='store_true',
                       help='Validate all official URLs and exit')
    
    # Output directory options
    parser.add_argument('--windows-output', type=Path, default=DEFAULT_WINDOWS_PATH)
    parser.add_argument('--darwin-output', type=Path, default=DEFAULT_DARWIN_PATH)
    parser.add_argument('--linux-output', type=Path, default=DEFAULT_LINUX_PATH)
    
    # Target platform for conversion (auto-mapped from source platform)
    parser.add_argument('--target-platform', choices=['windows', 'darwin', 'linux'], 
                       help='Override target platform (auto-detected from --platform by default)')
    
    # Payload handling
    parser.add_argument('--payloads-dir', type=Path, 
                       help='Directory to copy payload files to (enables payload extraction and copying)')
    
    # Execution options
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--force', action='store_true', help='Overwrite existing files')
    
    return parser


def main() -> None:
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Handle utility options
    if args.list_platforms:
        print_available_platforms()
        sys.exit(0)
    
    if args.validate_urls:
        validate_urls()
        sys.exit(0)
    
    # Require input source for conversion
    if not any([args.platform, args.index_url, args.index_file, args.all_platforms]):
        parser.error("Must specify one of: --platform, --index-url, --index-file, or --all-platforms")
    
    # Handle all-platforms mode
    if args.all_platforms:
        print("Processing all official atomic platforms (macos, windows, linux)")
        print("This will clone the repository once and process all index files")
        if args.payloads_dir:
            print(f"Payloads will be copied to: {args.payloads_dir}")
    elif args.platform:
        platform = Platform(args.platform)
        # Auto-map target platform if not specified
        if not args.target_platform:
            args.target_platform = platform.target_platform
        print(f"Using official {args.platform} atomic index from GitHub")
        print(f"URL: {ATOMIC_INDEX_URLS[args.platform]}")
        print(f"Auto-mapped target platform: {args.platform} → {args.target_platform}")
    elif args.index_url:
        # Require explicit target platform for custom URLs
        if not args.target_platform:
            parser.error("--target-platform is required when using --index-url")
        print(f"Using custom index URL: {args.index_url}")
    else:
        # Require explicit target platform for local files
        if not args.target_platform:
            parser.error("--target-platform is required when using --index-file")
        print(f"Using local index file: {args.index_file}")
    
    # Create output directories
    output_dirs = {
        'windows': args.windows_output,
        'darwin': args.darwin_output,
        'linux': args.linux_output
    }
    
    for platform_name, path in output_dirs.items():
        path.mkdir(parents=True, exist_ok=True)
    
    # Convert
    converter = AtomicIndexConverter(verbose=args.verbose, force=args.force, payloads_dir=args.payloads_dir)
    
    try:
        if args.all_platforms:
            # Process all platforms with single repo clone
            for platform_name, output_path in output_dirs.items():
                print(f"{platform_name.capitalize()} output: {output_path}")
            print("Starting all-platform conversion...")
            
            stats = converter.convert_all_platforms(output_dirs)
        else:
            # Process single platform
            print(f"Target platform: {args.target_platform}")
            print(f"Output directory: {output_dirs[args.target_platform]}")
            if args.payloads_dir:
                print(f"Payloads directory: {args.payloads_dir}")
            print("Starting conversion...")
            
            platform = Platform(args.platform)
            stats = converter.convert_single_platform(platform, output_dirs)
        
        stats_dict = stats.to_dict()
        print(f"\nConversion Results:")
        print(f"  Processed: {stats_dict['processed']}")
        print(f"  Created: {stats_dict['created']}")
        print(f"  Skipped: {stats_dict['skipped']}")
        print(f"  Errors: {stats_dict['errors']}")
        
        # Success summary
        if stats_dict['created'] > 0:
            print(f"\nSUCCESS: Converted {stats_dict['created']} atomic tests to Caldera procedures")
            if args.all_platforms:
                print(f"Output directories:")
                for platform_name, output_path in output_dirs.items():
                    print(f"  {platform_name.capitalize()}: {output_path}")
                print(f"Source: All official atomic indexes (macos, windows, linux)")
            else:
                print(f"Output: {output_dirs[args.target_platform]}")
                if args.platform:
                    print(f"Source: Official {args.platform} atomic index")
        else:
            print(f"\nWARNING: No procedures were created. Check skip reasons above.")
            sys.exit(1)
        
    except Exception as e:
        print(f"\nERROR: Conversion failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 