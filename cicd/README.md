# CI/CD Pipeline

Automated weekly updates for Caldera procedure libraries from external security research projects.

## Automation

**Schedule**: Every Sunday at 2 AM UTC  
**Actions**: Downloads latest data, converts to Caldera format, updates repository and README badges

## Import Scripts

| Script | Source | Platform |
|--------|--------|----------|
| `import_lolbas_to_caldera.py` | [LOLBAS](https://lolbas-project.github.io/) | Windows |
| `import_loldrivers_to_caldera.py` | [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Windows |
| `import_loobins_to_caldera.py` | [LOOBins](https://github.com/infosecB/LOOBins) | macOS |
| `convert_loldrivers_to_caldera.py` | [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Windows |

## Setup

### Required Repository Settings
1. **GitHub Actions**: Enable with "Read and write permissions"
2. **Branch**: Allow Actions to push to main branch

### Dependencies
- Python 3.9+
- Packages: `pyyaml`, `requests`, `mitreattack-python`

### Files
- `requirements.txt` - Python dependencies
- `config.py` - Environment configuration
- `.github/workflows/update-procedures.yml` - Main automation
- `.github/workflows/test-imports.yml` - Manual testing

## Usage

**Automatic**: Runs every Sunday at 2 AM UTC  
**Manual**: GitHub Actions → "Update Procedure Libraries" → "Run workflow"

## Troubleshooting

- **No changes**: Normal if external sources have no updates
- **Script failures**: Individual failures won't stop the pipeline
- **MITRE data**: Automatically downloads if missing
- **Logs**: Check GitHub Actions for detailed error information 