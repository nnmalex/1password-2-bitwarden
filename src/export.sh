#!/bin/bash
# 1Password Export Script
# READ-ONLY operations only - exports all vaults and items to JSON files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXPORT_DIR="$PROJECT_DIR/data/export"
ATTACHMENTS_DIR="$PROJECT_DIR/data/attachments"
LOG_FILE="$PROJECT_DIR/logs/migration.log"

# Initialize directories
mkdir -p "$EXPORT_DIR" "$ATTACHMENTS_DIR" "$PROJECT_DIR/logs"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Starting 1Password Export ==="

# Check 1Password CLI authentication
if ! op whoami &>/dev/null; then
    log "ERROR: 1Password CLI not authenticated. Please run 'op signin' first."
    exit 1
fi

log "1Password CLI authenticated successfully"

# Export vault list
log "Exporting vault list..."
op vault list --format json > "$EXPORT_DIR/vaults.json"
VAULT_COUNT=$(jq length "$EXPORT_DIR/vaults.json")
log "Found $VAULT_COUNT vaults"

# Process each vault
TOTAL_ITEMS=0
TOTAL_DOCUMENTS=0

for vault_id in $(jq -r '.[].id' "$EXPORT_DIR/vaults.json"); do
    vault_name=$(jq -r ".[] | select(.id == \"$vault_id\") | .name" "$EXPORT_DIR/vaults.json")
    log "Processing vault: $vault_name ($vault_id)"
    
    # Create vault directory
    vault_dir="$EXPORT_DIR/$vault_id"
    mkdir -p "$vault_dir"
    
    # Export item list for vault
    log "  Exporting item list..."
    op item list --vault "$vault_id" --format json > "$vault_dir/items.json"
    item_count=$(jq length "$vault_dir/items.json")
    log "  Found $item_count items"
    TOTAL_ITEMS=$((TOTAL_ITEMS + item_count))
    
    # Export full details for each item
    log "  Exporting item details..."
    item_index=0
    for item_id in $(jq -r '.[].id' "$vault_dir/items.json"); do
        item_index=$((item_index + 1))
        
        # Get full item details
        op item get "$item_id" --format json > "$vault_dir/$item_id.json" 2>/dev/null || {
            log "  WARNING: Failed to export item $item_id"
            continue
        }
        
        # Check for documents/attachments
        item_category=$(jq -r '.category' "$vault_dir/$item_id.json")
        if [ "$item_category" = "DOCUMENT" ]; then
            item_title=$(jq -r '.title' "$vault_dir/$item_id.json")
            log "  Found document: $item_title"
            
            # Create safe filename
            safe_title=$(echo "$item_title" | tr -cd '[:alnum:]._-' | head -c 200)
            attachment_dir="$ATTACHMENTS_DIR/$vault_id"
            mkdir -p "$attachment_dir"
            
            # Download document
            op document get "$item_id" --output "$attachment_dir/${item_id}_${safe_title}" 2>/dev/null && {
                log "  Downloaded document: $item_title"
                TOTAL_DOCUMENTS=$((TOTAL_DOCUMENTS + 1))
            } || {
                log "  WARNING: Failed to download document $item_id"
            }
        fi
        
        # Check for file attachments on items
        if jq -e '.files' "$vault_dir/$item_id.json" &>/dev/null; then
            item_title=$(jq -r '.title' "$vault_dir/$item_id.json")
            log "  Item '$item_title' has file attachments"
            
            attachment_dir="$ATTACHMENTS_DIR/$vault_id"
            mkdir -p "$attachment_dir"
            
            for file_id in $(jq -r '.files[].id' "$vault_dir/$item_id.json" 2>/dev/null); do
                file_name=$(jq -r ".files[] | select(.id == \"$file_id\") | .name" "$vault_dir/$item_id.json")
                op document get "$file_id" --output "$attachment_dir/${item_id}_${file_name}" 2>/dev/null && {
                    log "  Downloaded attachment: $file_name"
                    TOTAL_DOCUMENTS=$((TOTAL_DOCUMENTS + 1))
                } || {
                    log "  WARNING: Failed to download attachment $file_id"
                }
            done
        fi
        
        # Progress indicator every 100 items
        if [ $((item_index % 100)) -eq 0 ]; then
            log "  Progress: $item_index / $item_count items"
        fi
    done
    
    log "  Completed vault: $vault_name"
done

log "=== Export Complete ==="
log "Total vaults: $VAULT_COUNT"
log "Total items: $TOTAL_ITEMS"
log "Total documents/attachments: $TOTAL_DOCUMENTS"
log "Export directory: $EXPORT_DIR"
log "Attachments directory: $ATTACHMENTS_DIR"

# Create export summary
cat > "$EXPORT_DIR/summary.json" << EOF
{
  "export_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "vault_count": $VAULT_COUNT,
  "item_count": $TOTAL_ITEMS,
  "document_count": $TOTAL_DOCUMENTS,
  "export_dir": "$EXPORT_DIR",
  "attachments_dir": "$ATTACHMENTS_DIR"
}
EOF

log "Export summary saved to $EXPORT_DIR/summary.json"
