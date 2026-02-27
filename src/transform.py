#!/usr/bin/env python3
"""
1Password to Bitwarden Data Transformation Script

Converts exported 1Password JSON data to Bitwarden-compatible format.
Reads vault mapping configuration from config.json.

Usage:
    python3 transform.py [--config path/to/config.json]
"""

import json
import sys
import re
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Dict, List
import uuid
import logging

# Bitwarden item types
BW_TYPE_LOGIN = 1
BW_TYPE_SECURE_NOTE = 2
BW_TYPE_CARD = 3
BW_TYPE_IDENTITY = 4
BW_TYPE_SSH_KEY = 5

# 1Password category to Bitwarden type mapping
CATEGORY_MAP = {
    'LOGIN': BW_TYPE_LOGIN,
    'PASSWORD': BW_TYPE_LOGIN,
    'SECURE_NOTE': BW_TYPE_SECURE_NOTE,
    'CREDIT_CARD': BW_TYPE_CARD,
    'IDENTITY': BW_TYPE_IDENTITY,
    'SSH_KEY': BW_TYPE_SSH_KEY,
    # These map to login with custom fields
    'API_CREDENTIAL': BW_TYPE_LOGIN,
    'DATABASE': BW_TYPE_LOGIN,
    'SERVER': BW_TYPE_LOGIN,
    'WIRELESS_ROUTER': BW_TYPE_LOGIN,
    'REWARD_PROGRAM': BW_TYPE_LOGIN,
    'MEMBERSHIP': BW_TYPE_LOGIN,
    # These map to secure notes with custom fields
    'SOFTWARE_LICENSE': BW_TYPE_SECURE_NOTE,
    'PASSPORT': BW_TYPE_IDENTITY,
    'DRIVER_LICENSE': BW_TYPE_IDENTITY,
    'SOCIAL_SECURITY_NUMBER': BW_TYPE_SECURE_NOTE,
    'MEDICAL_RECORD': BW_TYPE_SECURE_NOTE,
    'BANK_ACCOUNT': BW_TYPE_SECURE_NOTE,
    'DOCUMENT': BW_TYPE_SECURE_NOTE,
}


def load_config(config_path: Path) -> Dict:
    """Load vault mapping configuration from config.json."""
    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            "Please create config.json with your vault mapping. See README.md for examples."
        )
    
    with open(config_path) as f:
        config = json.load(f)
    
    if 'vault_mapping' not in config:
        raise ValueError("config.json must contain 'vault_mapping' key")
    
    return config['vault_mapping']


class OnePasswordToBitwarden:
    """Transform 1Password data to Bitwarden format."""
    
    def __init__(self, export_dir: Path, output_dir: Path, vault_mapping: Dict, logger: logging.Logger):
        self.export_dir = export_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vault_mapping = vault_mapping
        self.logger = logger
        
        self.vault_name_to_id: Dict[str, str] = {}  # vault_id -> vault_name
        self.folders: Dict[str, Dict] = {}  # folder_name -> folder_info
        self.collections: Dict[str, Dict] = {}  # collection_name -> collection_info
        
        # Separate item lists by destination
        self.personal_items: List[Dict] = []
        self.org_items: List[Dict] = []
        
        self.attachments: List[Dict] = []  # Track items with attachments
        self.stats = {
            'total_items': 0,
            'converted': 0,
            'failed': 0,
            'by_vault': {},
            'by_type': {}
        }
    
    def generate_uuid(self) -> str:
        """Generate a Bitwarden-compatible UUID."""
        return str(uuid.uuid4())
    
    def transform_all(self) -> bool:
        """Transform all vaults and items."""
        self.logger.info("Starting transformation...")
        
        # Load vaults
        vaults_file = self.export_dir / 'vaults.json'
        if not vaults_file.exists():
            self.logger.error(f"Vaults file not found: {vaults_file}")
            return False
        
        with open(vaults_file) as f:
            vaults = json.load(f)
        
        # Build vault name mapping
        for vault in vaults:
            self.vault_name_to_id[vault['id']] = vault['name']
            self.logger.info(f"Found vault: {vault['name']} ({vault['id']})")
        
        # Create folders and collections based on mapping
        for vault_name, mapping in self.vault_mapping.items():
            if mapping.get('folder'):
                folder_id = self.generate_uuid()
                self.folders[mapping['folder']] = {
                    'id': folder_id,
                    'name': mapping['folder']
                }
                self.logger.info(f"Created folder mapping: {mapping['folder']} -> {folder_id}")
            
            if mapping.get('collection'):
                collection_id = self.generate_uuid()
                self.collections[mapping['collection']] = {
                    'id': collection_id,
                    'name': mapping['collection'],
                    'organizationId': None,  # Will be set during import
                }
                self.logger.info(f"Created collection mapping: {mapping['collection']} -> {collection_id}")
        
        # Process each vault
        for vault in vaults:
            self.transform_vault(vault)
        
        # Save transformed data
        self.save_output()
        
        # Print statistics
        self.print_stats()
        
        return True
    
    def get_vault_mapping(self, vault_id: str) -> Dict:
        """Get the mapping configuration for a vault."""
        vault_name = self.vault_name_to_id.get(vault_id, '')
        default_mapping = {
            'destination': 'personal',
            'folder': None,
            'organization': None,
            'collection': None,
        }
        return self.vault_mapping.get(vault_name, default_mapping)
    
    def transform_vault(self, vault: Dict):
        """Transform all items in a vault."""
        vault_id = vault['id']
        vault_name = vault['name']
        vault_dir = self.export_dir / vault_id
        
        mapping = self.get_vault_mapping(vault_id)
        dest_info = f"-> {mapping['destination']}"
        if mapping.get('folder'):
            dest_info += f" (folder: {mapping['folder']})"
        if mapping.get('organization'):
            dest_info += f" (org: {mapping['organization']}, collection: {mapping.get('collection')})"
        
        self.logger.info(f"Processing vault: {vault_name} {dest_info}")
        
        if not vault_dir.exists():
            self.logger.warning(f"Vault directory not found: {vault_dir}")
            return
        
        # Load items list
        items_file = vault_dir / 'items.json'
        if not items_file.exists():
            self.logger.warning(f"Items file not found: {items_file}")
            return
        
        with open(items_file) as f:
            items_list = json.load(f)
        
        # Initialize vault stats
        self.stats['by_vault'][vault_name] = {'total': 0, 'converted': 0, 'failed': 0}
        
        # Process each item
        for item_summary in items_list:
            item_id = item_summary['id']
            item_file = vault_dir / f'{item_id}.json'
            
            if not item_file.exists():
                self.logger.warning(f"Item file not found: {item_file}")
                continue
            
            try:
                with open(item_file) as f:
                    item = json.load(f)
                
                self.stats['total_items'] += 1
                self.stats['by_vault'][vault_name]['total'] += 1
                
                bw_item = self.transform_item(item, vault_id, mapping)
                
                if bw_item:
                    # Add to appropriate list based on destination
                    if mapping['destination'] == 'organization':
                        self.org_items.append(bw_item)
                    else:
                        self.personal_items.append(bw_item)
                    
                    self.stats['converted'] += 1
                    self.stats['by_vault'][vault_name]['converted'] += 1
                    
                    # Track type statistics
                    category = item.get('category', 'UNKNOWN')
                    self.stats['by_type'][category] = self.stats['by_type'].get(category, 0) + 1
                else:
                    self.stats['failed'] += 1
                    self.stats['by_vault'][vault_name]['failed'] += 1
                    
            except Exception as e:
                self.logger.error(f"Failed to transform item {item_id}: {e}")
                self.stats['failed'] += 1
                self.stats['by_vault'][vault_name]['failed'] += 1
    
    def transform_item(self, item: Dict, vault_id: str, mapping: Dict) -> Optional[Dict]:
        """Transform a single 1Password item to Bitwarden format."""
        category = item.get('category', 'SECURE_NOTE')
        bw_type = CATEGORY_MAP.get(category, BW_TYPE_SECURE_NOTE)
        
        # Determine folder/collection ID
        folder_id = None
        collection_ids = None
        organization_id = None
        
        if mapping['destination'] == 'personal' and mapping.get('folder'):
            folder_info = self.folders.get(mapping['folder'])
            if folder_info:
                folder_id = folder_info['id']
        elif mapping['destination'] == 'organization' and mapping.get('collection'):
            collection_info = self.collections.get(mapping['collection'])
            if collection_info:
                collection_ids = [collection_info['id']]
        
        # Base Bitwarden item structure
        bw_item = {
            'id': self.generate_uuid(),
            'organizationId': organization_id,
            'folderId': folder_id,
            'collectionIds': collection_ids,
            'type': bw_type,
            'reprompt': 0,
            'name': item.get('title', 'Untitled'),
            'notes': self.get_notes(item),
            'favorite': False,
            'fields': [],
            'creationDate': item.get('created_at'),
            'revisionDate': item.get('updated_at'),
            # Store original vault info for reference
            '_source_vault': self.vault_name_to_id.get(vault_id, 'Unknown'),
            '_source_id': item.get('id'),
        }
        
        # Add type-specific data
        if bw_type == BW_TYPE_LOGIN:
            bw_item['login'] = self.transform_login(item)
        elif bw_type == BW_TYPE_CARD:
            bw_item['card'] = self.transform_card(item)
        elif bw_type == BW_TYPE_IDENTITY:
            bw_item['identity'] = self.transform_identity(item, category)
        elif bw_type == BW_TYPE_SECURE_NOTE:
            bw_item['secureNote'] = {'type': 0}
        elif bw_type == BW_TYPE_SSH_KEY:
            bw_item['sshKey'] = self.transform_ssh_key(item)
        
        # Add custom fields for non-standard fields
        custom_fields = self.extract_custom_fields(item, category)
        if custom_fields:
            bw_item['fields'] = custom_fields
        
        # Track attachments
        if item.get('files'):
            self.attachments.append({
                'op_item_id': item['id'],
                'bw_item_id': bw_item['id'],
                'files': item['files'],
                'destination': mapping['destination'],
            })
        
        return bw_item
    
    def get_notes(self, item: Dict) -> Optional[str]:
        """Extract notes from 1Password item."""
        fields = item.get('fields', [])
        for field in fields:
            if field.get('purpose') == 'NOTES' and field.get('value'):
                return field['value']
        return None
    
    def get_field_value(self, item: Dict, field_id: str = None, purpose: str = None, 
                        field_type: str = None, label: str = None) -> Optional[str]:
        """Get a field value by various criteria."""
        fields = item.get('fields', [])
        for field in fields:
            if field_id and field.get('id') == field_id:
                return field.get('value')
            if purpose and field.get('purpose') == purpose:
                return field.get('value')
            if field_type and field.get('type') == field_type:
                return field.get('value')
            if label and field.get('label') == label:
                return field.get('value')
        return None
    
    def transform_login(self, item: Dict) -> Dict:
        """Transform to Bitwarden login type."""
        login: Dict[str, Any] = {
            'username': None,
            'password': None,
            'totp': None,
            'uris': []
        }
        
        # Get username
        login['username'] = self.get_field_value(item, purpose='USERNAME')
        
        # Get password
        login['password'] = self.get_field_value(item, purpose='PASSWORD')
        
        # Get TOTP
        totp_value = self.get_field_value(item, field_type='OTP')
        if totp_value:
            # Extract secret from otpauth URL
            match = re.search(r'secret=([A-Z2-7]+)', totp_value, re.IGNORECASE)
            if match:
                login['totp'] = match.group(1)
            else:
                login['totp'] = totp_value
        
        # Get URLs
        urls = item.get('urls', [])
        for url in urls:
            href = url.get('href')
            if href:
                login['uris'].append({
                    'uri': href,
                    'match': None
                })
        
        return login
    
    def transform_card(self, item: Dict) -> Dict:
        """Transform to Bitwarden card type."""
        card: Dict[str, Any] = {
            'cardholderName': None,
            'brand': None,
            'number': None,
            'expMonth': None,
            'expYear': None,
            'code': None
        }
        
        fields = item.get('fields', [])
        for field in fields:
            field_id = field.get('id', '')
            field_type = field.get('type', '')
            value = field.get('value')
            
            if field_id == 'cardholder' or 'cardholder' in field.get('label', '').lower():
                card['cardholderName'] = value
            elif field_id == 'ccnum' or field_type == 'CREDIT_CARD_NUMBER':
                card['number'] = value
            elif field_id == 'cvv' or 'verification' in field.get('label', '').lower():
                card['code'] = value
            elif field_id == 'expiry' or field_type == 'MONTH_YEAR':
                if value:
                    # Parse YYYYMM format
                    value_str = str(value)
                    if len(value_str) >= 6:
                        card['expYear'] = value_str[:4]
                        card['expMonth'] = value_str[4:6].lstrip('0') or '1'
            elif field_id == 'type' or field_type == 'CREDIT_CARD_TYPE':
                card['brand'] = value
        
        return card
    
    def transform_identity(self, item: Dict, category: str) -> Dict:
        """Transform to Bitwarden identity type."""
        identity: Dict[str, Any] = {
            'title': None,
            'firstName': None,
            'middleName': None,
            'lastName': None,
            'address1': None,
            'address2': None,
            'address3': None,
            'city': None,
            'state': None,
            'postalCode': None,
            'country': None,
            'company': None,
            'email': None,
            'phone': None,
            'ssn': None,
            'username': None,
            'passportNumber': None,
            'licenseNumber': None
        }
        
        fields = item.get('fields', [])
        for field in fields:
            field_id = field.get('id', '')
            label = field.get('label', '').lower()
            value = field.get('value')
            
            if not value:
                continue
            
            # Map common identity fields
            if 'firstname' in field_id or 'first' in label:
                identity['firstName'] = value
            elif 'lastname' in field_id or 'last' in label:
                identity['lastName'] = value
            elif 'email' in field_id or 'email' in label:
                identity['email'] = value
            elif 'phone' in field_id or 'phone' in label:
                identity['phone'] = value
            elif 'address' in field_id or 'street' in label:
                if not identity['address1']:
                    identity['address1'] = value
                elif not identity['address2']:
                    identity['address2'] = value
            elif 'city' in field_id or 'city' in label:
                identity['city'] = value
            elif 'state' in field_id or 'state' in label or 'province' in label:
                identity['state'] = value
            elif 'zip' in field_id or 'postal' in label:
                identity['postalCode'] = value
            elif 'country' in field_id or 'country' in label:
                identity['country'] = value
            elif 'company' in field_id or 'company' in label:
                identity['company'] = value
            elif 'ssn' in field_id or 'social' in label:
                identity['ssn'] = value
            elif 'passport' in label or category == 'PASSPORT':
                if 'number' in label:
                    identity['passportNumber'] = value
            elif 'license' in label or category == 'DRIVER_LICENSE':
                if 'number' in label:
                    identity['licenseNumber'] = value
        
        return identity
    
    def transform_ssh_key(self, item: Dict) -> Dict:
        """Transform to Bitwarden SSH key type."""
        ssh_key: Dict[str, Any] = {
            'privateKey': None,
            'publicKey': None,
            'keyFingerprint': None
        }
        
        fields = item.get('fields', [])
        for field in fields:
            field_id = field.get('id', '')
            field_type = field.get('type', '')
            value = field.get('value')
            
            if field_id == 'private_key' or field_type == 'SSHKEY':
                ssh_key['privateKey'] = value
            elif field_id == 'public_key':
                ssh_key['publicKey'] = value
            elif field_id == 'fingerprint':
                ssh_key['keyFingerprint'] = value
        
        return ssh_key
    
    def extract_custom_fields(self, item: Dict, category: str) -> List[Dict]:
        """Extract non-standard fields as custom fields."""
        custom_fields = []
        
        # Standard fields to skip (already mapped)
        skip_purposes = {'USERNAME', 'PASSWORD', 'NOTES'}
        skip_ids = {'username', 'password', 'notesPlain', 'cardholder', 'ccnum', 
                    'cvv', 'expiry', 'validFrom', 'type', 'private_key', 'public_key', 
                    'fingerprint', 'key_type'}
        skip_types = {'OTP', 'CREDIT_CARD_NUMBER', 'CREDIT_CARD_TYPE', 'SSHKEY'}
        
        fields = item.get('fields', [])
        for field in fields:
            # Skip standard fields
            if field.get('purpose') in skip_purposes:
                continue
            if field.get('id') in skip_ids:
                continue
            if field.get('type') in skip_types:
                continue
            
            value = field.get('value')
            label = field.get('label', field.get('id', 'Unknown'))
            
            # Skip empty fields
            if not value or not label:
                continue
            
            # Determine field type
            field_type = 0  # Text
            if field.get('type') == 'CONCEALED':
                field_type = 1  # Hidden
            
            custom_fields.append({
                'name': label,
                'value': str(value),
                'type': field_type,
                'linkedId': None
            })
        
        return custom_fields
    
    def save_output(self):
        """Save transformed data to output files."""
        # Save folders
        folders_list = list(self.folders.values())
        with open(self.output_dir / 'folders.json', 'w') as f:
            json.dump(folders_list, f, indent=2)
        self.logger.info(f"Saved {len(folders_list)} folders")
        
        # Save collections
        collections_list = list(self.collections.values())
        with open(self.output_dir / 'collections.json', 'w') as f:
            json.dump(collections_list, f, indent=2)
        self.logger.info(f"Saved {len(collections_list)} collections")
        
        # Save personal vault items
        with open(self.output_dir / 'personal_items.json', 'w') as f:
            json.dump(self.personal_items, f, indent=2)
        self.logger.info(f"Saved {len(self.personal_items)} personal vault items")
        
        # Save organization items
        with open(self.output_dir / 'org_items.json', 'w') as f:
            json.dump(self.org_items, f, indent=2)
        self.logger.info(f"Saved {len(self.org_items)} organization items")
        
        # Save all items combined (for reference)
        all_items = self.personal_items + self.org_items
        with open(self.output_dir / 'items.json', 'w') as f:
            json.dump(all_items, f, indent=2)
        
        # Save attachments mapping
        with open(self.output_dir / 'attachments.json', 'w') as f:
            json.dump(self.attachments, f, indent=2)
        self.logger.info(f"Saved {len(self.attachments)} attachment mappings")
        
        # Save Bitwarden import format for personal vault
        personal_export = {
            'encrypted': False,
            'folders': folders_list,
            'items': self.personal_items,
        }
        with open(self.output_dir / 'bitwarden_personal_import.json', 'w') as f:
            json.dump(personal_export, f, indent=2)
        self.logger.info("Saved Bitwarden personal import file")
        
        # Save Bitwarden import format for organization
        org_export = {
            'encrypted': False,
            'collections': collections_list,
            'items': self.org_items,
        }
        with open(self.output_dir / 'bitwarden_org_import.json', 'w') as f:
            json.dump(org_export, f, indent=2)
        self.logger.info("Saved Bitwarden organization import file")
        
        # Save summary
        summary = {
            'transform_date': datetime.now(timezone.utc).isoformat(),
            'personal_items': len(self.personal_items),
            'org_items': len(self.org_items),
            'total_items': len(self.personal_items) + len(self.org_items),
            'folders': len(folders_list),
            'collections': len(collections_list),
            'attachments': len(self.attachments),
            'vault_mapping': self.vault_mapping,
        }
        with open(self.output_dir / 'summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
    
    def print_stats(self):
        """Print transformation statistics."""
        self.logger.info("=== Transformation Statistics ===")
        self.logger.info(f"Total items processed: {self.stats['total_items']}")
        self.logger.info(f"Successfully converted: {self.stats['converted']}")
        self.logger.info(f"Failed: {self.stats['failed']}")
        self.logger.info(f"Personal vault items: {len(self.personal_items)}")
        self.logger.info(f"Organization items: {len(self.org_items)}")
        self.logger.info("")
        self.logger.info("By vault:")
        for vault_name, counts in self.stats['by_vault'].items():
            self.logger.info(f"  {vault_name}: {counts['converted']}/{counts['total']} converted")
        self.logger.info("")
        self.logger.info("By item type:")
        for item_type, count in sorted(self.stats['by_type'].items()):
            self.logger.info(f"  {item_type}: {count}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Transform 1Password export to Bitwarden format'
    )
    parser.add_argument(
        '--config', '-c',
        type=Path,
        help='Path to config.json (default: project_dir/config.json)'
    )
    args = parser.parse_args()
    
    # Determine paths
    project_dir = Path(__file__).parent.parent
    export_dir = project_dir / 'data' / 'export'
    output_dir = project_dir / 'data' / 'transformed'
    log_dir = project_dir / 'logs'
    config_path = args.config or (project_dir / 'config.json')
    
    # Ensure directories exist
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'migration.log'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    
    # Load configuration
    try:
        vault_mapping = load_config(config_path)
        logger.info(f"Loaded configuration from {config_path}")
        logger.info(f"Vault mappings: {list(vault_mapping.keys())}")
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        sys.exit(1)
    
    # Check if export exists
    if not export_dir.exists():
        logger.error(f"Export directory not found: {export_dir}")
        logger.error("Please run export.sh first")
        sys.exit(1)
    
    # Run transformation
    transformer = OnePasswordToBitwarden(export_dir, output_dir, vault_mapping, logger)
    
    if transformer.transform_all():
        logger.info("")
        logger.info("Transformation complete!")
        logger.info(f"Output saved to: {output_dir}")
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Import personal items: bw import bitwardenjson data/transformed/bitwarden_personal_import.json")
        logger.info("  2. Import org items: bw import bitwardenjson data/transformed/bitwarden_org_import.json --organizationid <org-id>")
    else:
        logger.error("Transformation failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
