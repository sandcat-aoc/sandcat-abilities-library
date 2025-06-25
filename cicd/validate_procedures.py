#!/usr/bin/env python3

import yaml
import glob
import sys
import os

def validate_procedure_schema(file_path):
    """Validate procedure file against expected Caldera schema"""
    try:
        with open(file_path, 'r') as f:
            procedures = yaml.safe_load(f)
        
        if not isinstance(procedures, list) or len(procedures) != 1:
            return 'INVALID: Must contain exactly one procedure in a list'
            
        procedure = procedures[0]
        
        # Required fields
        required_fields = ['id', 'name', 'description', 'tactic', 'technique', 'platforms']
        missing_fields = [field for field in required_fields if field not in procedure]
        if missing_fields:
            return f'MISSING FIELDS: {missing_fields}'
            
        # Technique structure
        if not isinstance(procedure.get('technique'), dict):
            return 'INVALID: technique must be a dict'
        if 'attack_id' not in procedure['technique'] or 'name' not in procedure['technique']:
            return 'INVALID: technique missing attack_id or name'
            
        # Platforms structure
        if not isinstance(procedure.get('platforms'), dict):
            return 'INVALID: platforms must be a dict'
            
        # Check platform executors
        for platform, executors in procedure['platforms'].items():
            if not isinstance(executors, dict):
                return f'INVALID: platform {platform} executors must be a dict'
            for executor_name, executor_data in executors.items():
                if not isinstance(executor_data, dict):
                    return f'INVALID: executor {executor_name} must be a dict'
                if 'command' not in executor_data:
                    return f'INVALID: executor {executor_name} missing command'
                if 'cleanup' in executor_data and isinstance(executor_data['cleanup'], list):
                    return 'INVALID: cleanup must be string, not list'
                    
        return 'VALID'
        
    except Exception as e:
        return f'ERROR: {str(e)}'

def main():
    # Validate all attackmacos procedure files
    procedure_files = glob.glob('data/procedures/**/*.yml', recursive=True)
    print(f'Validating {len(procedure_files)} attackmacos procedure files...')
    print()

    valid_count = 0
    invalid_files = []

    for file_path in sorted(procedure_files):
        result = validate_procedure_schema(file_path)
        file_name = file_path.split('/')[-1]
        
        if result == 'VALID':
            valid_count += 1
            print(f'[PASS] {file_name}')
        else:
            invalid_files.append((file_name, result))
            print(f'[FAIL] {file_name}: {result}')

    print()
    print('VALIDATION SUMMARY:')
    print(f'Valid files: {valid_count}/{len(procedure_files)}')
    print(f'Invalid files: {len(invalid_files)}')

    if invalid_files:
        print()
        print('ISSUES FOUND:')
        for file_name, issue in invalid_files:
            print(f'  - {file_name}: {issue}')
        return 1
    else:
        print()
        print('SUCCESS: All procedure files pass schema validation.')
        return 0

if __name__ == '__main__':
    sys.exit(main()) 