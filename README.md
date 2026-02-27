# 1Password to Bitwarden Migration Tool

A command-line tool to migrate your data from 1Password to Bitwarden, preserving folder structure, custom fields, TOTP secrets, and more.

## Features

- Exports all items from 1Password vaults via CLI
- Transforms data to Bitwarden-compatible format
- Supports flexible vault-to-destination mapping:
  - Personal vault (with or without folders)
  - Organization vaults with collections
- Preserves:
  - Logins (username, password, URLs, TOTP)
  - Credit cards
  - Identities
  - Secure notes
  - SSH keys
  - Software licenses (as secure notes with custom fields)
  - Custom fields on all item types

## Requirements

- **1Password CLI** (`op`) - [Install guide](https://developer.1password.com/docs/cli/get-started/)
- **Bitwarden CLI** (`bw`) - [Install guide](https://bitwarden.com/help/cli/)
- **Python 3.6+**
- **jq** - JSON processor (`brew install jq` on macOS)

## Quick Start

### 1. Install CLIs

```bash
# macOS with Homebrew
brew install 1password-cli bitwarden-cli jq

# Verify installation
op --version
bw --version
```

### 2. Authenticate

```bash
# 1Password - sign in and export session
eval $(op signin)

# Bitwarden - login and unlock
bw login
export BW_SESSION=$(bw unlock --raw)
```

### 3. Configure Vault Mapping

Edit `config.json` to map your 1Password vaults to Bitwarden destinations:

```json
{
  "vault_mapping": {
    "Personal": {
      "destination": "personal",
      "folder": null
    },
    "Work": {
      "destination": "personal",
      "folder": "Work"
    },
    "Family": {
      "destination": "organization",
      "organization": "Family Org",
      "collection": "Shared"
    }
  }
}
```

### 4. Run Migration

```bash
# Full migration (export + transform + import)
./src/migrate.sh

# Or run steps individually:
./src/export.sh      # Export from 1Password
python3 src/transform.py  # Transform to Bitwarden format
./src/import.sh      # Import to Bitwarden
```

## Configuration

### Vault Mapping Options

| Option | Description |
|--------|-------------|
| `destination` | `"personal"` or `"organization"` |
| `folder` | Folder name for personal vault (null for no folder) |
| `organization` | Organization name (required if destination is "organization") |
| `collection` | Collection name within organization |

### Example Configurations

**All to personal vault, no folders:**
```json
{
  "vault_mapping": {
    "Private": {"destination": "personal", "folder": null},
    "Work": {"destination": "personal", "folder": null}
  }
}
```

**Vaults to folders:**
```json
{
  "vault_mapping": {
    "Private": {"destination": "personal", "folder": null},
    "Work": {"destination": "personal", "folder": "Work"},
    "Finance": {"destination": "personal", "folder": "Finance"}
  }
}
```

**Mixed personal and organization:**
```json
{
  "vault_mapping": {
    "Private": {"destination": "personal", "folder": null},
    "Family": {
      "destination": "organization",
      "organization": "Family",
      "collection": "Shared Logins"
    }
  }
}
```

## Item Type Mapping

| 1Password Type | Bitwarden Type |
|---------------|----------------|
| Login | Login |
| Password | Login |
| Credit Card | Card |
| Identity | Identity |
| Secure Note | Secure Note |
| SSH Key | SSH Key |
| Software License | Secure Note + Custom Fields |
| API Credential | Login + Custom Fields |
| Database | Login + Custom Fields |
| Server | Login + Custom Fields |
| Document | Secure Note (attachment separate) |

## Limitations

### Cannot Be Migrated

- **Passkeys** - Cannot be exported due to WebAuthn security design. You must manually re-register passkeys on each site.
- **Document attachments** - May fail to download via CLI for some document types. Check logs and transfer manually if needed.
- **Watchtower data** - 1Password's security reports don't transfer (Bitwarden has its own).
- **Password history** - Not fully preserved in migration.

### Known Issues

- Duplicate folders may be created if a folder with the same name already exists
- Large vaults (1000+ items) may take 20-30 minutes to export

## File Structure

```
1pe/
├── README.md           # This file
├── config.json         # Vault mapping configuration
├── src/
│   ├── export.sh       # 1Password export (READ-ONLY)
│   ├── transform.py    # Data transformation
│   ├── import.sh       # Bitwarden import
│   └── migrate.sh      # Main orchestrator
├── data/
│   ├── export/         # Exported 1Password data
│   ├── attachments/    # Downloaded attachments
│   └── transformed/    # Bitwarden-ready JSON
├── logs/
│   └── migration.log   # Operation logs
└── reports/
    ├── pre-migration.md
    └── post-migration.md
```

## Security Notes

1. **Exported data contains secrets** - The `data/export/` directory contains all your passwords in plain text. Delete it after migration.

2. **1Password is READ-ONLY** - This tool never modifies or deletes anything in 1Password.

3. **Test first** - Run `./src/export.sh` alone first to see what will be migrated before importing.

4. **Bitwarden is reversible** - If something goes wrong, you can delete imported items from Bitwarden and try again.

## Troubleshooting

### "You are not currently signed in"

```bash
eval $(op signin)
```

### "Bitwarden vault is locked"

```bash
export BW_SESSION=$(bw unlock --raw)
```

### Export is slow

This is normal. The 1Password CLI fetches each item individually. Expect ~1 second per item.

### Missing items after import

1. Check `logs/migration.log` for errors
2. Verify item counts: `bw list items | jq length`
3. Run `bw sync` to refresh

## Contributing

Issues and pull requests welcome!

## License

MIT License - See LICENSE file
