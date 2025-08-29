#!/bin/bash

# Script to fix APT sources for Debian 9 (stretch)
# This script will only run on Debian GNU/Linux 9 (stretch)

set -e  # Exit on any error

# Function to check if running as root
check_root() {
    # Check if the effective user ID is not 0 (root)
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect OS version
check_debian_stretch() {
    # Check if the /etc/os-release file exists (contains OS info)
    if [ ! -f /etc/os-release ]; then
        echo "Cannot determine OS version - /etc/os-release not found"
        echo "Exiting without making changes."
        exit 0
    fi
    
    # Source the os-release file to get OS variables
    . /etc/os-release
    
    # Check if it's Debian 9 (stretch)
    if [ "$ID" != "debian" ] || [ "$VERSION_ID" != "9" ]; then
        echo "This script is designed for Debian GNU/Linux 9 (stretch) only"
        echo "Current OS: $PRETTY_NAME"
        echo "Exiting without making changes."
        exit 0
    fi
    
    # Print detected OS
    echo "Detected: $PRETTY_NAME - proceeding with APT sources fix..."
}

# Function to backup current sources.list
backup_sources() {
    # If sources.list exists, back it up with a timestamp
    if [ -f /etc/apt/sources.list ]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.backup.$(date +%Y%m%d_%H%M%S)
        echo "Backed up current sources.list"
    fi
}

# Main execution logic
main() {
    echo "=== Debian 9 (Stretch) APT Sources Fix Script ==="
    echo
    
    # Check if running as root
    check_root
    
    # Check if OS is Debian 9 (stretch)
    check_debian_stretch
    
    # Backup current sources.list
    backup_sources
    
    # Step 1: Disable buster.list if present (not needed for stretch)
    echo "Step 1: Disabling buster.list file..."
    if [ -f /etc/apt/sources.list.d/buster.list ]; then
        mv /etc/apt/sources.list.d/buster.list /etc/apt/sources.list.d/buster.list.disabled
        echo "✓ Moved buster.list to buster.list.disabled"
    else
        echo "ℹ buster.list not found - skipping"
    fi
    
    echo
    # Step 2: Overwrite sources.list with archived stretch repositories
    echo "Step 2: Updating sources.list with archive repositories..."
    echo -e "deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main" | tee /etc/apt/sources.list
    echo "✓ Updated sources.list"
    
    echo
    # Step 3: Configure APT to allow unauthenticated and expired repos (required for archived repos)
    echo "Step 3: Configuring APT to work with archived repositories..."
    echo -e 'APT::Get::AllowUnauthenticated "true";\nAcquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\nAcquire::AllowDowngradeToInsecureRepositories "true";' | tee /etc/apt/apt.conf.d/99allow-unauthenticated
    echo "✓ Created APT configuration for archived repositories"
    
    echo
    # Step 4: Clean APT cache to avoid issues with old lists
    echo "Step 4: Cleaning APT cache..."
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    echo "✓ Cleaned APT cache"
    
    echo
    # Step 5: Update package lists from the new sources
    echo "Step 5: Updating package lists..."
    if apt-get update; then
        echo "✓ Successfully updated package lists"
        echo
        echo "=== APT Sources Fix Complete ==="
        echo "Your Debian 9 (stretch) system is now configured to use archived repositories."
        echo
        echo "⚠️  IMPORTANT SECURITY WARNING:"
        echo "   Debian 9 reached end-of-life in July 2022 and no longer receives security updates."
        echo "   Consider upgrading to a supported Debian version (11 or 12) for production use."
    else
        echo "✗ Failed to update package lists"
        echo "Check the error messages above for details."
        exit 1
    fi
}

# Run main function
main