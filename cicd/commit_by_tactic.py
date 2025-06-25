#!/usr/bin/env python3
"""
Intelligent Tactic-based Commit Tool for Caldera Procedures Library.
Commits procedures grouped by MITRE ATT&CK tactic to create clean commit history.
"""

import sys
from pathlib import Path
import subprocess

try:
    import git
    from git import Repo
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "GitPython"])
    import git
    from git import Repo


class TacticCommitter:
    def __init__(self, repo_path: str = "."):
        self.repo = Repo(repo_path)
        self.repo_path = Path(repo_path).resolve()
        print(f"Repository: {self.repo_path}")
    
    def get_modified_procedures_by_tactic(self):
        """Get modified procedure files organized by tactic."""
        modified_files = []
        
        # Get untracked, modified, and staged files
        modified_files.extend(self.repo.untracked_files)
        modified_files.extend([item.a_path for item in self.repo.index.diff(None)])
        modified_files.extend([item.a_path for item in self.repo.index.diff('HEAD')])
        
        # Filter for procedure files
        procedure_files = [f for f in modified_files 
                          if f.endswith('.yml') and 
                          any(platform in f for platform in ['abilities/windows/', 'abilities/darwin/', 'abilities/linux/'])]
        
        print(f"Found {len(procedure_files)} modified procedure files")
        
        # Group by tactic
        tactic_groups = {}
        for file_path in procedure_files:
            path_parts = Path(file_path).parts
            if len(path_parts) >= 4:  # abilities/platform/tactic/file.yml
                tactic = path_parts[2]
                if tactic not in tactic_groups:
                    tactic_groups[tactic] = []
                tactic_groups[tactic].append(file_path)
        
        return dict(sorted(tactic_groups.items(), key=lambda x: len(x[1]), reverse=True))
    
    def count_platforms_in_tactic(self, file_paths):
        """Count procedures per platform in a tactic."""
        platform_counts = {'windows': 0, 'darwin': 0, 'linux': 0}
        for file_path in file_paths:
            for platform in platform_counts.keys():
                if file_path.startswith(f"abilities/{platform}/"):
                    platform_counts[platform] += 1
                    break
        return platform_counts
    
    def generate_tactic_commit_message(self, tactic: str, file_paths):
        """Generate commit message for a tactic group."""
        total_procedures = len(file_paths)
        platform_counts = self.count_platforms_in_tactic(file_paths)
        
        tactic_display = tactic.replace('-', ' ').replace('_', ' ').title()
        title = f"Add {tactic_display} procedures ({total_procedures} procedures)"
        
        details = [f"Added {total_procedures} {tactic_display.lower()} procedures across platforms:", ""]
        
        for platform, count in platform_counts.items():
            if count > 0:
                platform_display = "macOS" if platform == "darwin" else platform.title()
                details.append(f"- {platform_display}: {count} procedures")
        
        details.extend([
            "",
            "Sources: Atomic Red Team, LOLBAS, LOLDrivers, LOOBins, Attack-macOS",
            "All procedures follow standardized YAML format with MITRE ATT&CK mapping"
        ])
        
        return title + "\n\n" + "\n".join(details)
    
    def commit_tactic_group(self, tactic: str, file_paths):
        """Commit all procedures for a specific tactic."""
        try:
            print(f"\nProcessing {tactic} tactic ({len(file_paths)} procedures)")
            
            platform_counts = self.count_platforms_in_tactic(file_paths)
            for platform, count in platform_counts.items():
                if count > 0:
                    platform_display = "macOS" if platform == "darwin" else platform.title()
                    print(f"   {platform_display}: {count}")
            
            commit_message = self.generate_tactic_commit_message(tactic, file_paths)
            
            print(f"\nCommit message preview:")
            print("-" * 50)
            preview = commit_message.split('\n')[0]  # Just show title
            print(preview)
            print("-" * 50)
            
            response = input(f"\nCommit {len(file_paths)} {tactic} procedures? [y/N]: ").strip().lower()
            
            if response not in ['y', 'yes']:
                print(f"Skipped {tactic}")
                return False
            
            self.repo.index.add(file_paths)
            self.repo.index.commit(commit_message)
            
            print(f"Committed {tactic} ({len(file_paths)} procedures)")
            return True
            
        except Exception as e:
            print(f"Error committing {tactic}: {e}")
            return False


def main():
    print("TacticCommitter - Intelligent Tactic-based Git Commit Tool")
    print("=" * 65)
    print("Commits procedures grouped by MITRE ATT&CK tactic for clean history")
    
    try:
        committer = TacticCommitter()
    except Exception as e:
        print(f"Error: {e}")
        return
    
    tactic_groups = committer.get_modified_procedures_by_tactic()
    
    if not tactic_groups:
        print("No modified procedure files found")
        return
    
    total_procedures = sum(len(files) for files in tactic_groups.values())
    print(f"\nFound {total_procedures} procedures across {len(tactic_groups)} tactics:")
    
    for tactic, files in tactic_groups.items():
        platform_counts = committer.count_platforms_in_tactic(files)
        active_platforms = [p for p, c in platform_counts.items() if c > 0]
        print(f"   {tactic}: {len(files)} procedures ({', '.join(active_platforms)})")
    
    print(f"\nThis will create {len(tactic_groups)} meaningful commits instead of 1 massive commit")
    
    proceed = input("\nProceed with tactic-based commits? [y/N]: ").strip().lower()
    if proceed not in ['y', 'yes']:
        print("Exiting")
        return
    
    total_commits = 0
    for tactic, files in tactic_groups.items():
        if committer.commit_tactic_group(tactic, files):
            total_commits += 1
    
    print(f"\nSummary: Completed {total_commits} commits")
    
    if total_commits > 0:
        print("All commits are ready locally")
        push_response = input("\nPush all commits to remote? [y/N]: ").strip().lower()
        if push_response in ['y', 'yes']:
            try:
                origin = committer.repo.remote('origin')
                print("Pushing to remote...")
                origin.push()
                print("Successfully pushed to remote")
            except Exception as e:
                print(f"Error pushing: {e}")
                print("You can manually push with: git push origin main")
        else:
            print("Commits are ready locally. Push manually when ready.")


if __name__ == "__main__":
    main() 