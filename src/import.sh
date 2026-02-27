#!/bin/bash
# Bitwarden Import Script
# Imports transformed data into Bitwarden

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TRANSFORMED_DIR="$PROJECT_DIR/data/transformed"
ATTACHMENTS_DIR="$PROJECT_DIR/data/attachments"
LOG_FILE="$PROJECT_DIR/logs/migration.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Starting Bitwarden Import ==="

# Check Bitwarden CLI status
BW_STATUS=$(bw status 2>&1 | jq -r '.status')
if [ "$BW_STATUS" != "unlocked" ]; then
    log "ERROR: Bitwarden vault is not unlocked. Please run 'bw unlock' first."
    log "Current status: $BW_STATUS"
    exit 1
fi

log "Bitwarden CLI unlocked"

# Check if session is set
if [ -z "$BW_SESSION" ]; then
    log "WARNING: BW_SESSION environment variable not set."
    log "Please export BW_SESSION from 'bw unlock' output"
    exit 1
fi

# Verify transformed data exists
if [ ! -f "$TRANSFORMED_DIR/bitwarden_import.json" ]; then
    log "ERROR: Transformed data not found at $TRANSFORMED_DIR/bitwarden_import.json"
    log "Please run transform.py first"
    exit 1
fi

# Sync Bitwarden first
log "Syncing Bitwarden vault..."
bw sync

# Get current item count for comparison
ITEMS_BEFORE=$(bw list items 2>/dev/null | jq length)
log "Current Bitwarden items: $ITEMS_BEFORE"

# Import method selection
IMPORT_METHOD="${1:-bulk}"

if [ "$IMPORT_METHOD" = "bulk" ]; then
    log "Using bulk import method..."
    
    # Use Bitwarden's import command with JSON format
    log "Importing from bitwarden_import.json..."
    bw import bitwardenjson "$TRANSFORMED_DIR/bitwarden_import.json" 2>&1 | tee -a "$LOG_FILE"
    
elif [ "$IMPORT_METHOD" = "individual" ]; then
    log "Using individual item import method..."
    
    # Create folders first
    log "Creating folders..."
    if [ -f "$TRANSFORMED_DIR/folders.json" ]; then
        for folder in $(jq -c '.[]' "$TRANSFORMED_DIR/folders.json"); do
            folder_name=$(echo "$folder" | jq -r '.name')
            log "  Creating folder: $folder_name"
            
            # Check if folder already exists
            existing=$(bw list folders 2>/dev/null | jq -r ".[] | select(.name == \"$folder_name\") | .id")
            
            if [ -z "$existing" ]; then
                folder_json=$(echo "{\"name\":\"$folder_name\"}" | bw encode)
                bw create folder "$folder_json" 2>/dev/null || log "  WARNING: Failed to create folder $folder_name"
            else
                log "  Folder already exists: $folder_name"
            fi
        done
    fi
    
    # Sync to get folder IDs
    bw sync
    
    # Import items one by one
    log "Importing items..."
    ITEM_COUNT=0
    ITEM_FAILED=0
    
    for item in $(jq -c '.[]' "$TRANSFORMED_DIR/items.json"); do
        item_name=$(echo "$item" | jq -r '.name')
        ITEM_COUNT=$((ITEM_COUNT + 1))
        
        # Update folder ID to actual Bitwarden folder ID
        folder_id=$(echo "$item" | jq -r '.folderId')
        if [ "$folder_id" != "null" ]; then
            # Find the folder name from our mapping
            original_folder=$(jq -r ".[] | select(.id == \"$folder_id\") | .name" "$TRANSFORMED_DIR/folders.json" 2>/dev/null)
            if [ -n "$original_folder" ]; then
                actual_folder_id=$(bw list folders 2>/dev/null | jq -r ".[] | select(.name == \"$original_folder\") | .id")
                if [ -n "$actual_folder_id" ]; then
                    item=$(echo "$item" | jq ".folderId = \"$actual_folder_id\"")
                fi
            fi
        fi
        
        # Remove our custom id (Bitwarden will assign its own)
        item=$(echo "$item" | jq 'del(.id) | del(.creationDate) | del(.revisionDate)')
        
        # Encode and create
        item_json=$(echo "$item" | bw encode)
        
        if bw create item "$item_json" >/dev/null 2>&1; then
            log "  [$ITEM_COUNT] Created: $item_name"
        else
            log "  [$ITEM_COUNT] FAILED: $item_name"
            ITEM_FAILED=$((ITEM_FAILED + 1))
        fi
        
        # Progress every 50 items
        if [ $((ITEM_COUNT % 50)) -eq 0 ]; then
            log "  Progress: $ITEM_COUNT items processed"
        fi
    done
    
    log "Items created: $((ITEM_COUNT - ITEM_FAILED))"
    log "Items failed: $ITEM_FAILED"
    
else
    log "ERROR: Unknown import method: $IMPORT_METHOD"
    log "Usage: $0 [bulk|individual]"
    exit 1
fi

# Sync and verify
log "Syncing Bitwarden..."
bw sync

ITEMS_AFTER=$(bw list items 2>/dev/null | jq length)
ITEMS_ADDED=$((ITEMS_AFTER - ITEMS_BEFORE))

log "=== Import Complete ==="
log "Items before import: $ITEMS_BEFORE"
log "Items after import: $ITEMS_AFTER"
log "Items added: $ITEMS_ADDED"

# Handle attachments
if [ -f "$TRANSFORMED_DIR/attachments.json" ]; then
    ATTACHMENT_COUNT=$(jq length "$TRANSFORMED_DIR/attachments.json")
    if [ "$ATTACHMENT_COUNT" -gt 0 ]; then
        log ""
        log "=== Attachments ==="
        log "Found $ATTACHMENT_COUNT items with attachments"
        log "Attachments must be uploaded manually or with a separate script"
        log "Attachment files are in: $ATTACHMENTS_DIR"
    fi
fi
