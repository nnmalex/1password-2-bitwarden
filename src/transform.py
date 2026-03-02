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
import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
import uuid
import logging

# Bitwarden item types
BW_TYPE_LOGIN = 1
BW_TYPE_SECURE_NOTE = 2
BW_TYPE_CARD = 3
BW_TYPE_IDENTITY = 4
BW_TYPE_SSH_KEY = 5


class SSHKeyProcessor:
    """Helper class to process and validate SSH keys for Bitwarden compatibility."""
    
    # OpenSSH private key headers
    OPENSSH_PRIVATE_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
    OPENSSH_PRIVATE_END = "-----END OPENSSH PRIVATE KEY-----"
    
    # Legacy PEM format headers
    RSA_PRIVATE_BEGIN = "-----BEGIN RSA PRIVATE KEY-----"
    RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----"
    EC_PRIVATE_BEGIN = "-----BEGIN EC PRIVATE KEY-----"
    EC_PRIVATE_END = "-----END EC PRIVATE KEY-----"
    PKCS8_PRIVATE_BEGIN = "-----BEGIN PRIVATE KEY-----"
    PKCS8_PRIVATE_END = "-----END PRIVATE KEY-----"
    
    # Public key prefixes for different key types
    PUBLIC_KEY_PREFIXES = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 
                          'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-dss']
    
    @classmethod
    def is_valid_private_key(cls, key: Optional[str]) -> bool:
        """Check if the provided string is a valid SSH private key."""
        if not key or not isinstance(key, str):
            return False
        
        key = key.strip()
        
        # Check for OpenSSH format
        if cls.OPENSSH_PRIVATE_BEGIN in key and cls.OPENSSH_PRIVATE_END in key:
            return True
        
        # Check for legacy PEM formats
        if cls.RSA_PRIVATE_BEGIN in key and cls.RSA_PRIVATE_END in key:
            return True
        if cls.EC_PRIVATE_BEGIN in key and cls.EC_PRIVATE_END in key:
            return True
        if cls.PKCS8_PRIVATE_BEGIN in key and cls.PKCS8_PRIVATE_END in key:
            return True
        
        return False
    
    @classmethod
    def is_valid_public_key(cls, key: Optional[str]) -> bool:
        """Check if the provided string is a valid SSH public key."""
        if not key or not isinstance(key, str):
            return False
        
        key = key.strip()
        
        # Check if it starts with a known public key prefix
        for prefix in cls.PUBLIC_KEY_PREFIXES:
            if key.startswith(prefix):
                return True
        
        return False
    
    @classmethod
    def normalize_private_key(cls, key: Optional[str]) -> Optional[str]:
        """Normalize a private key to ensure proper formatting."""
        if not key:
            return None
        
        key = key.strip()
        
        # If it's already a valid private key, ensure proper line endings
        if cls.is_valid_private_key(key):
            # Normalize line endings
            key = key.replace('\r\n', '\n').replace('\r', '\n')
            return key
        
        # Try to wrap raw base64 content in OpenSSH headers
        # This handles cases where 1Password might export just the key material
        if cls._looks_like_base64(key):
            # Try wrapping as OpenSSH format
            wrapped = f"{cls.OPENSSH_PRIVATE_BEGIN}\n{cls._format_base64(key)}\n{cls.OPENSSH_PRIVATE_END}"
            return wrapped
        
        return None
    
    @classmethod
    def normalize_public_key(cls, key: Optional[str]) -> Optional[str]:
        """Normalize a public key to ensure proper formatting."""
        if not key:
            return None
        
        key = key.strip()
        
        # Remove any newlines from the public key (should be single line)
        key = key.replace('\n', '').replace('\r', '')
        
        if cls.is_valid_public_key(key):
            return key
        
        return None
    
    @classmethod
    def generate_fingerprint(cls, public_key: Optional[str], private_key: Optional[str] = None) -> Optional[str]:
        """
        Generate an SSH key fingerprint from the public key.
        
        Returns fingerprint in SHA256:base64 format (e.g., "SHA256:abcd1234...")
        Falls back to using ssh-keygen if available.
        """
        if public_key and cls.is_valid_public_key(public_key):
            fingerprint = cls._generate_fingerprint_from_public_key(public_key)
            if fingerprint:
                return fingerprint
        
        # Try using ssh-keygen with the private key
        if private_key and cls.is_valid_private_key(private_key):
            fingerprint = cls._generate_fingerprint_via_ssh_keygen(private_key)
            if fingerprint:
                return fingerprint
        
        return None
    
    @classmethod
    def _generate_fingerprint_from_public_key(cls, public_key: str) -> Optional[str]:
        """Generate fingerprint directly from public key data."""
        try:
            # Parse the public key: format is "type base64data [comment]"
            parts = public_key.strip().split()
            if len(parts) < 2:
                return None
            
            key_type = parts[0]
            key_data = parts[1]
            
            # Decode the base64 key data
            raw_key = base64.b64decode(key_data)
            
            # Generate SHA256 hash
            sha256_hash = hashlib.sha256(raw_key).digest()
            
            # Encode as base64 and format
            fingerprint_b64 = base64.b64encode(sha256_hash).decode('ascii').rstrip('=')
            
            return f"SHA256:{fingerprint_b64}"
        except Exception:
            return None
    
    @classmethod
    def _generate_fingerprint_via_ssh_keygen(cls, private_key: str) -> Optional[str]:
        """Generate fingerprint using ssh-keygen command."""
        try:
            # Write private key to a temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(private_key)
                temp_path = f.name
            
            try:
                # Use ssh-keygen to get fingerprint
                result = subprocess.run(
                    ['ssh-keygen', '-l', '-f', temp_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    # Output format: "256 SHA256:xxxx comment (TYPE)"
                    output = result.stdout.strip()
                    parts = output.split()
                    if len(parts) >= 2:
                        # Find the SHA256: part
                        for part in parts:
                            if part.startswith('SHA256:'):
                                return part
            finally:
                # Clean up temp file
                Path(temp_path).unlink(missing_ok=True)
        except Exception:
            pass
        
        return None
    
    @classmethod
    def extract_public_key_from_private(cls, private_key: str) -> Optional[str]:
        """Extract public key from a private key using ssh-keygen."""
        if not cls.is_valid_private_key(private_key):
            return None
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(private_key)
                temp_path = f.name
            
            try:
                # Set proper permissions for ssh-keygen
                Path(temp_path).chmod(0o600)
                
                # Extract public key
                result = subprocess.run(
                    ['ssh-keygen', '-y', '-f', temp_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    public_key = result.stdout.strip()
                    if cls.is_valid_public_key(public_key):
                        return public_key
            finally:
                Path(temp_path).unlink(missing_ok=True)
        except Exception:
            pass
        
        return None
    
    @classmethod
    def _looks_like_base64(cls, s: str) -> bool:
        """Check if a string looks like base64 encoded data."""
        # Remove whitespace
        s = ''.join(s.split())
        
        # Check if it's valid base64 characters
        import re
        if not re.match(r'^[A-Za-z0-9+/=]+$', s):
            return False
        
        # Should be reasonably long for an SSH key
        return len(s) > 100
    
    @classmethod
    def _format_base64(cls, data: str, line_length: int = 70) -> str:
        """Format base64 data with proper line breaks."""
        # Remove existing whitespace
        data = ''.join(data.split())
        
        # Insert line breaks
        lines = [data[i:i+line_length] for i in range(0, len(data), line_length)]
        return '\n'.join(lines)
    
    @classmethod
    def process_ssh_key(cls, private_key: Optional[str], public_key: Optional[str], 
                       fingerprint: Optional[str], logger: logging.Logger) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Process and validate SSH key data for Bitwarden compatibility.
        
        Returns: (normalized_private_key, normalized_public_key, fingerprint)
        """
        # Normalize private key
        normalized_private = cls.normalize_private_key(private_key)
        if not normalized_private:
            logger.warning("Could not normalize private key - key may be invalid or in unsupported format")
        
        # Normalize public key, or try to extract from private key
        normalized_public = cls.normalize_public_key(public_key)
        if not normalized_public and normalized_private:
            logger.info("Public key missing or invalid, attempting to extract from private key")
            normalized_public = cls.extract_public_key_from_private(normalized_private)
            if normalized_public:
                logger.info("Successfully extracted public key from private key")
            else:
                logger.warning("Could not extract public key from private key")
        
        # Generate or validate fingerprint
        if fingerprint:
            # Normalize fingerprint format
            if not fingerprint.startswith('SHA256:') and not fingerprint.startswith('MD5:'):
                # Might be just the hash portion, add SHA256 prefix
                if len(fingerprint) == 43 or len(fingerprint) == 44:  # Base64 SHA256 length
                    fingerprint = f"SHA256:{fingerprint}"
        else:
            # Generate fingerprint
            logger.info("Fingerprint missing, attempting to generate")
            fingerprint = cls.generate_fingerprint(normalized_public, normalized_private)
            if fingerprint:
                logger.info(f"Generated fingerprint: {fingerprint}")
            else:
                logger.warning("Could not generate fingerprint")
        
        return normalized_private, normalized_public, fingerprint
    
    @classmethod
    def validate_ssh_key_for_bitwarden(cls, private_key: Optional[str], public_key: Optional[str], 
                                       fingerprint: Optional[str]) -> Tuple[bool, List[str]]:
        """
        Validate that SSH key data meets Bitwarden requirements.
        
        Returns: (is_valid, list_of_issues)
        """
        issues = []
        
        if not private_key:
            issues.append("Missing private key")
        elif not cls.is_valid_private_key(private_key):
            issues.append("Private key is not in a valid format (OpenSSH or PKCS#8 required)")
        
        if not public_key:
            issues.append("Missing public key")
        elif not cls.is_valid_public_key(public_key):
            issues.append("Public key is not in a valid format")
        
        if not fingerprint:
            issues.append("Missing key fingerprint")
        
        return len(issues) == 0, issues

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
        self.ssh_key_warnings: List[str] = []  # Track SSH key issues
        self.stats = {
            'total_items': 0,
            'converted': 0,
            'failed': 0,
            'by_vault': {},
            'by_type': {},
            'ssh_keys': {
                'total': 0,
                'valid': 0,
                'with_warnings': 0
            }
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
            ssh_key_data, ssh_warnings = self.transform_ssh_key(item)
            bw_item['sshKey'] = ssh_key_data
            
            # Track SSH key statistics
            self.stats['ssh_keys']['total'] += 1
            if ssh_warnings:
                bw_item['_ssh_key_warnings'] = ssh_warnings
                self.ssh_key_warnings.extend(ssh_warnings)
                self.stats['ssh_keys']['with_warnings'] += 1
            else:
                self.stats['ssh_keys']['valid'] += 1
        
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
    
    def get_field_value(self, item: Dict, field_id: Optional[str] = None, purpose: Optional[str] = None, 
                        field_type: Optional[str] = None, label: Optional[str] = None) -> Optional[str]:
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
    
    def transform_ssh_key(self, item: Dict) -> Tuple[Dict, List[str]]:
        """
        Transform to Bitwarden SSH key type.
        
        Bitwarden's SSH Agent requires keys to be in OpenSSH or PKCS#8 format.
        This method:
        1. Extracts private key, public key, and fingerprint from 1Password fields
        2. Validates and normalizes the key format
        3. Generates missing public key from private key if needed
        4. Generates fingerprint if missing
        5. Validates all required fields are present
        
        Returns:
            Tuple of (ssh_key_dict, list_of_warnings)
        """
        warnings: List[str] = []
        
        # Initialize with None values
        raw_private_key: Optional[str] = None
        raw_public_key: Optional[str] = None
        raw_fingerprint: Optional[str] = None
        
        # Extract SSH key fields from 1Password item
        fields = item.get('fields', [])
        for field in fields:
            field_id = field.get('id', '').lower()
            field_type = field.get('type', '')
            field_label = field.get('label', '').lower()
            value = field.get('value')
            
            if not value:
                continue
            
            # Match private key by multiple criteria
            if (field_id == 'private_key' or
                field_id == 'privatekey' or
                field_type == 'SSHKEY' or
                'private key' in field_label):
                # Prefer OpenSSH format from ssh_formats if available
                # (Bitwarden SSH Agent requires OpenSSH format, not PKCS#8)
                ssh_formats = field.get('ssh_formats', {})
                openssh_data = ssh_formats.get('openssh', {})
                if openssh_data.get('value'):
                    raw_private_key = openssh_data['value']
                else:
                    raw_private_key = value
            # Match public key (use 'public key' not 'public' to avoid
            # matching unrelated fields like 'public url')
            elif (field_id == 'public_key' or
                  field_id == 'publickey' or
                  'public key' in field_label):
                raw_public_key = value
            # Match fingerprint
            elif (field_id == 'fingerprint' or
                  'fingerprint' in field_label):
                raw_fingerprint = value
        
        # Process and validate the SSH key data
        private_key, public_key, fingerprint = SSHKeyProcessor.process_ssh_key(
            raw_private_key, raw_public_key, raw_fingerprint, self.logger
        )
        
        # Validate the processed key
        is_valid, issues = SSHKeyProcessor.validate_ssh_key_for_bitwarden(
            private_key, public_key, fingerprint
        )
        
        if not is_valid:
            item_title = item.get('title', 'Unknown')
            for issue in issues:
                warning = f"SSH key '{item_title}': {issue}"
                warnings.append(warning)
                self.logger.warning(warning)
            
            # If private key is invalid but we have raw data, include a note
            if not private_key and raw_private_key:
                warnings.append(
                    f"SSH key '{item_title}': Private key exists but is not in OpenSSH/PKCS#8 format. "
                    "The key may not work with Bitwarden's SSH Agent. Consider manually recreating the key."
                )
        
        ssh_key: Dict[str, Any] = {
            'privateKey': private_key,
            'publicKey': public_key,
            'keyFingerprint': fingerprint
        }
        
        return ssh_key, warnings
    
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
            'ssh_keys': self.stats['ssh_keys'],
            'ssh_key_warnings': self.ssh_key_warnings,
        }
        with open(self.output_dir / 'summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Save SSH key warnings to a separate file for easy review
        if self.ssh_key_warnings:
            with open(self.output_dir / 'ssh_key_warnings.txt', 'w') as f:
                f.write("SSH Key Migration Warnings\n")
                f.write("=" * 50 + "\n\n")
                f.write("The following SSH keys may not work correctly with Bitwarden's SSH Agent.\n")
                f.write("Consider manually recreating these keys in Bitwarden after import.\n\n")
                for warning in self.ssh_key_warnings:
                    f.write(f"- {warning}\n")
            self.logger.warning(f"SSH key warnings saved to: {self.output_dir / 'ssh_key_warnings.txt'}")
    
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
        
        # SSH key specific stats
        ssh_stats = self.stats['ssh_keys']
        if ssh_stats['total'] > 0:
            self.logger.info("")
            self.logger.info("=== SSH Key Migration Summary ===")
            self.logger.info(f"Total SSH keys: {ssh_stats['total']}")
            self.logger.info(f"Valid (ready for SSH Agent): {ssh_stats['valid']}")
            self.logger.info(f"With warnings: {ssh_stats['with_warnings']}")
            
            if ssh_stats['with_warnings'] > 0:
                self.logger.warning("")
                self.logger.warning("WARNING: Some SSH keys may not work with Bitwarden's SSH Agent!")
                self.logger.warning("These keys require proper OpenSSH or PKCS#8 format to function.")
                self.logger.warning("Keys with issues may need to be manually recreated in Bitwarden.")
                self.logger.warning(f"See ssh_key_warnings.txt for details.")


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
