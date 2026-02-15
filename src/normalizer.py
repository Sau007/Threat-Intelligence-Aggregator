#!/usr/bin/env python3
"""
Data Normalizer Module
======================
Normalizes IOC indicators into a unified format with consistent
structure and metadata.
"""

import hashlib
import ipaddress
import logging
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse


class DataNormalizer:
    """
    Normalizes IOC indicators into a unified format.
    
    Adds metadata including:
    - Normalized type classification
    - Severity assessment
    - Timestamp
    - Source attribution
    - Hash for deduplication
    """
    
    # Severity mappings based on indicator characteristics
    SEVERITY_PATTERNS = {
        'high': [
            'malware', 'c2', 'botnet', 'ransomware', 'apt',
            'trojan', 'backdoor', 'rootkit'
        ],
        'medium': [
            'suspicious', 'phishing', 'spam', 'scanning',
            'brute-force', 'exploit'
        ],
        'low': [
            'info', 'reputation', 'proxy', 'vpn'
        ]
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def normalize(self, indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a single IOC indicator.
        
        Args:
            indicator: Raw indicator dictionary
            
        Returns:
            Normalized indicator dictionary or None if invalid
        """
        try:
            value = indicator.get('value', '').strip()
            
            if not value:
                return None
            
            # Determine IOC type
            ioc_type = self._determine_type(value, indicator.get('type', ''))
            
            # Create normalized structure
            normalized = {
                'id': self._generate_id(value, ioc_type),
                'value': value,
                'type': ioc_type,
                'category': self._determine_category(indicator),
                'severity': self._assess_severity(indicator),
                'confidence': self._assess_confidence(indicator),
                'source': indicator.get('source', 'unknown'),
                'first_seen': indicator.get('timestamp') or datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat(),
                'metadata': {
                    'original_type': indicator.get('type'),
                    'field': indicator.get('field'),
                    'stix_id': indicator.get('stix_id'),
                    'raw_context': indicator.get('raw_context', '')[:200]
                },
                'tags': self._extract_tags(indicator),
                'enrichment': self._enrich_indicator(value, ioc_type)
            }
            
            return normalized
            
        except Exception as e:
            self.logger.warning(f"Failed to normalize indicator: {e}")
            return None
    
    def _determine_type(self, value: str, original_type: str) -> str:
        """Determine the normalized type of an IOC."""
        original_lower = original_type.lower()
        
        # Map common type names
        type_mapping = {
            'ipv4-addr': 'ip',
            'ipv6-addr': 'ip',
            'ipv4': 'ip',
            'ipv6': 'ip',
            'ip': 'ip',
            'domain-name': 'domain',
            'domain': 'domain',
            'hostname': 'domain',
            'url': 'url',
            'uri': 'url',
            'md5': 'hash',
            'sha1': 'hash',
            'sha256': 'hash',
            'file-hash': 'hash',
            'hash': 'hash',
            'email-addr': 'email',
            'email': 'email',
        }
        
        # Check if original type can be mapped
        if original_lower in type_mapping:
            return type_mapping[original_lower]
        
        # Auto-detect from value
        if self._is_ip(value):
            return 'ip'
        elif self._is_hash(value):
            return 'hash'
        elif self._is_url(value):
            return 'url'
        elif self._is_email(value):
            return 'email'
        elif self._is_domain(value):
            return 'domain'
        
        return 'unknown'
    
    def _determine_category(self, indicator: Dict[str, Any]) -> str:
        """Determine the threat category."""
        category = indicator.get('category', '')
        
        if category:
            return category.lower()
        
        # Try to infer from context
        context = indicator.get('raw_context', '').lower()
        
        for severity, keywords in self.SEVERITY_PATTERNS.items():
            for keyword in keywords:
                if keyword in context:
                    return keyword
        
        return 'unknown'
    
    def _assess_severity(self, indicator: Dict[str, Any]) -> str:
        """Assess the severity of an indicator."""
        context = indicator.get('raw_context', '').lower()
        category = indicator.get('category', '').lower()
        
        # Check for high severity keywords
        for keyword in self.SEVERITY_PATTERNS['high']:
            if keyword in context or keyword in category:
                return 'high'
        
        # Check for medium severity keywords
        for keyword in self.SEVERITY_PATTERNS['medium']:
            if keyword in context or keyword in category:
                return 'medium'
        
        return 'low'
    
    def _assess_confidence(self, indicator: Dict[str, Any]) -> int:
        """Assess confidence level (0-100)."""
        confidence = 50  # Default medium confidence
        
        # Increase confidence if from reputable source
        reputable_sources = ['virustotal', 'abuseipdb', 'alienvault', 'misp']
        source = indicator.get('source', '').lower()
        
        if any(rs in source for rs in reputable_sources):
            confidence += 20
        
        # Increase if has STIX ID
        if indicator.get('stix_id'):
            confidence += 10
        
        # Increase if has category
        if indicator.get('category'):
            confidence += 10
        
        return min(100, confidence)
    
    def _extract_tags(self, indicator: Dict[str, Any]) -> list:
        """Extract tags from indicator data."""
        tags = []
        
        # Add type as tag
        ioc_type = indicator.get('type', '')
        if ioc_type:
            tags.append(ioc_type)
        
        # Add category as tag
        category = indicator.get('category', '')
        if category:
            tags.append(category.lower())
        
        # Extract additional tags from context
        context = indicator.get('raw_context', '').lower()
        tag_keywords = ['malware', 'phishing', 'botnet', 'c2', 'ransomware', 
                       'apt', 'trojan', 'exploit', 'spam', 'scanning']
        
        for keyword in tag_keywords:
            if keyword in context:
                tags.append(keyword)
        
        return list(set(tags))  # Remove duplicates
    
    def _enrich_indicator(self, value: str, ioc_type: str) -> Dict[str, Any]:
        """Enrich indicator with additional metadata."""
        enrichment = {}
        
        if ioc_type == 'ip':
            try:
                ip = ipaddress.ip_address(value)
                enrichment['version'] = 'IPv6' if isinstance(ip, ipaddress.IPv6Address) else 'IPv4'
                enrichment['is_private'] = ip.is_private
                enrichment['is_multicast'] = ip.is_multicast
                enrichment['is_reserved'] = ip.is_reserved
            except:
                pass
        
        elif ioc_type == 'hash':
            enrichment['hash_type'] = self._get_hash_type(value)
        
        elif ioc_type == 'url':
            try:
                parsed = urlparse(value)
                enrichment['scheme'] = parsed.scheme
                enrichment['netloc'] = parsed.netloc
                enrichment['path'] = parsed.path
            except:
                pass
        
        elif ioc_type == 'domain':
            parts = value.split('.')
            if len(parts) >= 2:
                enrichment['tld'] = parts[-1]
                enrichment['domain'] = '.'.join(parts[-2:])
        
        return enrichment
    
    def _generate_id(self, value: str, ioc_type: str) -> str:
        """Generate unique ID for indicator."""
        hash_input = f"{ioc_type}:{value.lower()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_hash(self, value: str) -> bool:
        """Check if value is a hash."""
        return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)
    
    def _is_url(self, value: str) -> bool:
        """Check if value is a URL."""
        return value.startswith(('http://', 'https://'))
    
    def _is_email(self, value: str) -> bool:
        """Check if value is an email."""
        return '@' in value and '.' in value.split('@')[-1]
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain."""
        if '.' not in value:
            return False
        if ' ' in value:
            return False
        return True
    
    def _get_hash_type(self, value: str) -> str:
        """Determine hash algorithm from length."""
        lengths = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}
        return lengths.get(len(value), 'UNKNOWN')
