#!/bin/bash

# Set source, destination, and backup directory
SOURCE_DIR="do178_trimmed_sources"
BACKUP_DIR="do178_backup"

# Ensure source directory exists
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Error: Source directory '$SOURCE_DIR' not found!"
    exit 1
fi

# Function to create a backup before overwriting
backup_files() {
    if [[ -d "$BACKUP_DIR" ]]; then
        echo "Warning: Previous backup exists at $BACKUP_DIR."
        read -p "Do you want to overwrite the existing backup? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            echo "Backup not overwritten. Exiting."
            exit 0
        fi
        rm -rf "$BACKUP_DIR"
    fi

    echo "Creating backup in $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    rsync -a --relative $(find "$SOURCE_DIR" -type f | sed "s|^$SOURCE_DIR/||") "$BACKUP_DIR"
    echo "✅ Backup completed."
}

# Function to copy files from trimmed sources
copy_files() {
    backup_files
    echo "Copying files from $SOURCE_DIR to current directory..."
    rsync -a --progress "$SOURCE_DIR/" ./
    echo "✅ Files have been copied. You can revert using: $0 --revert"
}

# Function to restore files from backup
revert_files() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        echo "Error: Backup directory '$BACKUP_DIR' not found! Nothing to revert."
        exit 1
    fi

    echo "Reverting changes from $BACKUP_DIR..."
    rsync -a --progress "$BACKUP_DIR/" ./
    echo "✅ Reverted to original files."
}

# Handle script options
case "$1" in
    --copy)
        copy_files
        ;;
    --revert)
        revert_files
        ;;
    *)
        echo "Usage: $0 --copy | --revert"
        echo "  --copy   Copy files from do178_trimmed_sources to current directory (with backup)"
        echo "  --revert Restore original files from backup"
        exit 1
        ;;
esac
