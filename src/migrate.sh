#!/bin/bash
# Main Migration Orchestrator
# Coordinates the full 1Password to Bitwarden migration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_DIR/logs/migration.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  1Password to Bitwarden Migration${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_step() {
    echo -e "\n${YELLOW}>>> $1${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check 1Password CLI
    if ! command -v op &> /dev/null; then
        print_error "1Password CLI (op) not found"
        exit 1
    fi
    print_success "1Password CLI found"
    
    # Check Bitwarden CLI
    if ! command -v bw &> /dev/null; then
        print_error "Bitwarden CLI (bw) not found"
        exit 1
    fi
    print_success "Bitwarden CLI found"
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        print_error "jq not found (required for JSON processing)"
        exit 1
    fi
    print_success "jq found"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found"
        exit 1
    fi
    print_success "Python 3 found"
    
    # Check 1Password authentication
    if ! op whoami &>/dev/null; then
        print_error "1Password not authenticated"
        echo "Please run: op signin"
        exit 1
    fi
    print_success "1Password authenticated"
    
    # Check Bitwarden status
    BW_STATUS=$(bw status 2>&1 | jq -r '.status')
    if [ "$BW_STATUS" != "unlocked" ]; then
        print_error "Bitwarden vault not unlocked (status: $BW_STATUS)"
        echo "Please run: bw unlock"
        exit 1
    fi
    print_success "Bitwarden unlocked"
    
    # Check BW_SESSION
    if [ -z "$BW_SESSION" ]; then
        print_warning "BW_SESSION not set"
        echo "Please export BW_SESSION from 'bw unlock' output"
        exit 1
    fi
    print_success "BW_SESSION is set"
}

run_export() {
    print_step "Phase 1: Exporting from 1Password..."
    
    if [ -f "$PROJECT_DIR/data/export/summary.json" ]; then
        echo "Previous export found. Re-export?"
        read -p "Enter 'yes' to re-export, or press Enter to skip: " response
        if [ "$response" != "yes" ]; then
            print_warning "Skipping export (using existing data)"
            return
        fi
    fi
    
    "$SCRIPT_DIR/export.sh"
    print_success "Export complete"
}

run_transform() {
    print_step "Phase 2: Transforming data..."
    
    if [ ! -f "$PROJECT_DIR/data/export/vaults.json" ]; then
        print_error "Export data not found. Please run export first."
        exit 1
    fi
    
    python3 "$SCRIPT_DIR/transform.py"
    print_success "Transformation complete"
}

run_import() {
    print_step "Phase 3: Importing to Bitwarden..."
    
    if [ ! -f "$PROJECT_DIR/data/transformed/bitwarden_import.json" ]; then
        print_error "Transformed data not found. Please run transform first."
        exit 1
    fi
    
    echo ""
    echo "Import method:"
    echo "  1) Bulk import (faster, recommended)"
    echo "  2) Individual item import (slower, better error handling)"
    echo ""
    read -p "Select method [1]: " method
    
    case "$method" in
        2)
            "$SCRIPT_DIR/import.sh" individual
            ;;
        *)
            "$SCRIPT_DIR/import.sh" bulk
            ;;
    esac
    
    print_success "Import complete"
}

verify_migration() {
    print_step "Phase 4: Verifying migration..."
    
    # Sync Bitwarden
    bw sync
    
    # Get counts
    OP_ITEMS=$(jq -r '.item_count' "$PROJECT_DIR/data/export/summary.json" 2>/dev/null || echo "unknown")
    BW_ITEMS=$(bw list items 2>/dev/null | jq length)
    BW_FOLDERS=$(bw list folders 2>/dev/null | jq length)
    
    echo ""
    echo "=== Migration Summary ==="
    echo ""
    echo "1Password items exported: $OP_ITEMS"
    echo "Bitwarden items: $BW_ITEMS"
    echo "Bitwarden folders: $BW_FOLDERS"
    echo ""
    
    # Generate post-migration report
    cat > "$PROJECT_DIR/reports/post-migration.md" << EOF
# Post-Migration Report

Generated: $(date '+%Y-%m-%d %H:%M:%S')

## Summary

| Metric | Count |
|--------|-------|
| 1Password items exported | $OP_ITEMS |
| Bitwarden items | $BW_ITEMS |
| Bitwarden folders | $BW_FOLDERS |

## Verification Checklist

- [ ] Item counts match expectations
- [ ] Folders created correctly
- [ ] Sample logins verified (username, password, URL)
- [ ] Sample credit cards verified
- [ ] Sample secure notes verified
- [ ] TOTP codes work correctly
- [ ] Attachments uploaded (if any)

## Notes

_Add any migration notes here_

## Issues

_Document any issues encountered_
EOF
    
    print_success "Verification report saved to reports/post-migration.md"
    
    if [ "$OP_ITEMS" != "unknown" ] && [ "$BW_ITEMS" -lt "$OP_ITEMS" ]; then
        print_warning "Bitwarden has fewer items than exported from 1Password"
        echo "This may be normal if some items already existed"
    fi
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all       - Run full migration (default)"
    echo "  export    - Export from 1Password only"
    echo "  transform - Transform data only"
    echo "  import    - Import to Bitwarden only"
    echo "  verify    - Verify migration only"
    echo "  help      - Show this help"
    echo ""
}

main() {
    # Initialize
    mkdir -p "$PROJECT_DIR/logs" "$PROJECT_DIR/reports"
    
    print_header
    log "=== Migration Started ==="
    
    command="${1:-all}"
    
    case "$command" in
        all)
            check_prerequisites
            run_export
            run_transform
            run_import
            verify_migration
            ;;
        export)
            check_prerequisites
            run_export
            ;;
        transform)
            run_transform
            ;;
        import)
            check_prerequisites
            run_import
            ;;
        verify)
            verify_migration
            ;;
        help|--help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
    
    log "=== Migration Finished ==="
    echo ""
    print_success "Migration complete!"
    echo ""
}

main "$@"
