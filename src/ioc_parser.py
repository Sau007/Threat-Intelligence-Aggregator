#!/usr/bin/env python3
"""
IOC Parser Module
=================
Parses various types of Indicators of Compromise (IOCs) from
different feed formats including IPs, domains, URLs, hashes, and emails.
"""

import hashlib
import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Union
from urllib.parse import urlparse


class IOCParser:
    """
    Parser for extracting IOCs from various feed formats.
    
    Supports:
    - IP addresses (IPv4 and IPv6)
    - Domain names
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    - Email addresses
    """
    
    # Regex patterns for IOC detection
    PATTERNS = {
        'ipv4': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ipv6': re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
            r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|'
            r'\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
        ),
        'domain': re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        ),
        'url': re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?)?'
        ),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'email': re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
    }
    
    # Private IP ranges to exclude
    PRIVATE_IPS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, data: Union[str, List, Dict], source: str) -> List[Dict[str, Any]]:
        """
        Parse IOCs from feed data.
        
        Args:
            data: Raw feed data (string, list, or dict)
            source: Source identifier for the feed
            
        Returns:
            List of parsed IOC dictionaries
        """
        indicators = []
        
        if isinstance(data, dict):
            indicators.extend(self._parse_dict(data, source))
        elif isinstance(data, list):
            indicators.extend(self._parse_list(data, source))
        elif isinstance(data, str):
            indicators.extend(self._parse_string(data, source))
        
        self.logger.info(f"Parsed {len(indicators)} indicators from {source}")
        return indicators
    
    def _parse_dict(self, data: Dict, source: str) -> List[Dict[str, Any]]:
        """Parse IOCs from dictionary format (JSON/STIX)."""
        indicators = []
        
        # Handle STIX format
        if 'objects' in data:
            for obj in data.get('objects', []):
                if obj.get('type') == 'indicator':
                    pattern = obj.get('pattern', '')
                    parsed = self._extract_from_pattern(pattern)
                    for ioc in parsed:
                        ioc['source'] = source
                        ioc['stix_id'] = obj.get('id')
                        ioc['created'] = obj.get('created')
                        indicators.append(ioc)
        
        # Handle MISP format
        elif 'Event' in data:
            event = data['Event']
            for attr in event.get('Attribute', []):
                ioc_type = self._classify_ioc_type(attr.get('value', ''))
                if ioc_type:
                    indicators.append({
                        'value': attr.get('value'),
                        'type': ioc_type,
                        'category': attr.get('category'),
                        'source': source,
                        'timestamp': attr.get('timestamp')
                    })
        
        # Generic dict parsing
        else:
            for key, value in data.items():
                if isinstance(value, str):
                    parsed = self._extract_from_string(value)
                    for ioc in parsed:
                        ioc['source'] = source
                        ioc['field'] = key
                        indicators.append(ioc)
        
        return indicators
    
    def _parse_list(self, data: List, source: str) -> List[Dict[str, Any]]:
        """Parse IOCs from list format (CSV rows)."""
        indicators = []
        
        for item in data:
            if isinstance(item, dict):
                indicators.extend(self._parse_dict(item, source))
            elif isinstance(item, list):
                # CSV row format
                for field in item:
                    if isinstance(field, str):
                        parsed = self._extract_from_string(field)
                        for ioc in parsed:
                            ioc['source'] = source
                            indicators.append(ioc)
            elif isinstance(item, str):
                parsed = self._extract_from_string(item)
                for ioc in parsed:
                    ioc['source'] = source
                    indicators.append(ioc)
        
        return indicators
    
    def _parse_string(self, data: str, source: str) -> List[Dict[str, Any]]:
        """Parse IOCs from plain text."""
        indicators = self._extract_from_string(data)
        for ioc in indicators:
            ioc['source'] = source
        return indicators
    
    def _extract_from_string(self, text: str) -> List[Dict[str, Any]]:
        """Extract IOCs from a text string."""
        indicators = []
        seen = set()
        
        # Extract each type of IOC
        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group()
                
                # Skip duplicates
                if value in seen:
                    continue
                seen.add(value)
                
                # Validate and add
                if self._validate_ioc(value, ioc_type):
                    indicators.append({
                        'value': value,
                        'type': ioc_type,
                        'raw_context': text[max(0, match.start()-50):min(len(text), match.end()+50)]
                    })
        
        return indicators
    
    def _extract_from_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Extract IOCs from STIX pattern."""
        indicators = []
        
        # STIX patterns look like: [ipv4-addr:value = '192.168.1.1']
        ioc_pattern = re.compile(r"'([^']+)'")
        type_pattern = re.compile(r'\[(\w+)')
        
        ioc_type_match = type_pattern.search(pattern)
        ioc_type = ioc_type_match.group(1) if ioc_type_match else 'unknown'
        
        for match in ioc_pattern.finditer(pattern):
            value = match.group(1)
            classified_type = self._classify_ioc_type(value)
            
            indicators.append({
                'value': value,
                'type': classified_type or ioc_type,
                'stix_pattern': pattern
            })
        
        return indicators
    
    def _validate_ioc(self, value: str, ioc_type: str) -> bool:
        """Validate an IOC value."""
        if ioc_type == 'ipv4':
            try:
                ip = ipaddress.ip_address(value)
                # Skip private IPs
                for private_net in self.PRIVATE_IPS:
                    if ip in private_net:
                        return False
                return True
            except ValueError:
                return False
        
        elif ioc_type == 'ipv6':
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                return False
        
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            # Validate hash format
            expected_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
            return len(value) == expected_lengths.get(ioc_type, 0)
        
        elif ioc_type == 'domain':
            # Skip common false positives
            false_positives = ['example.com', 'localhost', 'test.com']
            return value.lower() not in false_positives
        
        elif ioc_type == 'url':
            try:
                result = urlparse(value)
                return all([result.scheme, result.netloc])
            except:
                return False
        
        return True
    
    def _classify_ioc_type(self, value: str) -> str:
        """Classify the type of an IOC value."""
        for ioc_type, pattern in self.PATTERNS.items():
            if pattern.fullmatch(value):
                return ioc_type
        return 'unknown'
