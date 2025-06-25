#!/bin/bash

# Setup script for Caldera project virtual environment
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Function to print error messages
print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to print warning messages
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to print info messages
print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_info "Setting up procedure library Python environment..."

# Check Python version
print_status "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
MAJOR_VERSION=$(echo "$PYTHON_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$PYTHON_VERSION" | cut -d'.' -f2)

if [[ $MAJOR_VERSION -lt 3 ]] || [[ $MAJOR_VERSION -eq 3 && $MINOR_VERSION -lt 8 ]]; then
    print_error "Python 3.8 or higher is required (found: $PYTHON_VERSION)"
    exit 1
fi

print_status "Python $PYTHON_VERSION detected"

# Navigate to project root (parent of cicd directory)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

print_info "Working in project root: $PROJECT_ROOT"

# Check if we're in the correct procedures library directory
if [ ! -f "README.md" ] || [ ! -d "cicd" ]; then
    print_error "Must run from procedures library root directory"
    print_error "Expected files/directories: README.md, cicd/"
    exit 1
fi

# Create virtual environment
print_status "Creating virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists"
    read -p "Do you want to recreate it? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Removing existing virtual environment..."
        rm -rf venv
        python3 -m venv venv
    else
        print_info "Using existing virtual environment"
    fi
else
    python3 -m venv venv
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip and install essential tools
print_status "Upgrading pip and installing build tools..."
python3 -m pip install --upgrade pip wheel setuptools

# Install main requirements
print_status "Installing main requirements..."
if [ -f "cicd/requirements.txt" ]; then
    pip install -r cicd/requirements.txt
else
    print_warning "cicd/requirements.txt not found - installing basic dependencies"
    pip install PyYAML requests
fi

# Verify core dependencies
print_status "Verifying dependencies..."
python3 -c "
import sys
try:
    import yaml
    import requests
    print('Core dependencies verified')
except ImportError as e:
    print(f'Missing dependency: {e}')
    sys.exit(1)
" || {
    print_error "Failed to verify core dependencies"
    exit 1
}

# Display environment info
print_status "Environment setup complete!"
echo
print_info "Virtual environment location: $PROJECT_ROOT/venv"
print_info "Python version: $(python3 --version)"
print_info "Pip version: $(pip --version)"
echo
echo "📋 To use the environment:"
echo "   Activate:   source venv/bin/activate"
echo "   Deactivate: deactivate"
echo
echo "To run import scripts:"
echo "   cd cicd && python3 import_atomic_index_to_caldera.py ../macos-index.yaml -v" 