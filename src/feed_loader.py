#!/usr/bin/env python3
"""
Feed Loader Module
==================
Handles loading of IOC feeds from various sources including
local files and remote URLs.

Supports formats: CSV, JSON, TXT, STIX
"""

import csv
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Union
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class FeedLoader:
    """
    Loads threat intelligence feeds from files or URLs.
    
    Automatically detects format based on file extension or content.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.supported_formats = ['.csv', '.json', '.txt', '.stix']
    
    def load(self, source: str) -> Union[List, Dict, str]:
        """
        Load a feed from a file path or URL.
        
        Args:
            source: File path or URL to the feed
            
        Returns:
            Parsed feed data
            
        Raises:
            ValueError: If source type cannot be determined
            FileNotFoundError: If local file doesn't exist
        """
        self.logger.info(f"Loading feed from: {source}")
        
        # Determine if source is URL or file path
        if self._is_url(source):
            return self._load_from_url(source)
        else:
            return self._load_from_file(source)
    
    def _is_url(self, source: str) -> bool:
        """Check if source is a URL."""
        try:
            result = urlparse(source)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _load_from_url(self, url: str) -> Union[List, Dict, str]:
        """Load feed from a remote URL."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required for URL fetching. "
                            "Install with: pip install requests")
        
        try:
            self.logger.debug(f"Fetching URL: {url}")
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'ThreatIntelAggregator/1.0'
            })
            response.raise_for_status()
            
            # Determine format from content-type or URL
            content_type = response.headers.get('Content-Type', '')
            
            if 'json' in content_type or url.endswith('.json'):
                return response.json()
            elif 'csv' in content_type or url.endswith('.csv'):
                return list(csv.reader(response.text.splitlines()))
            else:
                return response.text
                
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch URL {url}: {e}")
            raise
    
    def _load_from_file(self, filepath: str) -> Union[List, Dict, str]:
        """Load feed from a local file."""
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Feed file not found: {filepath}")
        
        self.logger.debug(f"Reading file: {filepath}")
        
        # Determine format from extension
        extension = path.suffix.lower()
        
        try:
            if extension == '.json':
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
                    
            elif extension == '.csv':
                with open(path, 'r', encoding='utf-8') as f:
                    return list(csv.reader(f))
                    
            elif extension in ['.txt', '.stix', '.ioc']:
                with open(path, 'r', encoding='utf-8') as f:
                    return f.read()
                    
            else:
                # Try to auto-detect format
                content = path.read_text(encoding='utf-8')
                return self._auto_detect_format(content)
                
        except Exception as e:
            self.logger.error(f"Failed to read file {filepath}: {e}")
            raise
    
    def _auto_detect_format(self, content: str) -> Union[List, Dict, str]:
        """Attempt to auto-detect and parse format."""
        content = content.strip()
        
        # Try JSON first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Try CSV (check for comma-separated values)
        if ',' in content and '\n' in content:
            lines = content.split('\n')
            if len(lines) > 1:
                try:
                    return list(csv.reader(lines))
                except:
                    pass
        
        # Return as plain text
        return content


class FeedFormatDetector:
    """
    Detects the format of IOC feed content.
    """
    
    FORMAT_PATTERNS = {
        'json': r'^\s*[\{\[]',
        'csv': r'^[^,]+,[^,]+',
        'stix': r'<stix:STIX_Package|"type":\s*"bundle"',
        'misp': r'"Event":\s*\{',
        'taxii': r'<taxii_11:Discovery_Response',
        'plain_ip': r'^(\d{1,3}\.){3}\d{1,3}$',
        'plain_domain': r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$',
        'plain_hash': r'^[a-fA-F0-9]{32,64}$',
    }
    
    @classmethod
    def detect(cls, content: str) -> str:
        """
        Detect the format of feed content.
        
        Args:
            content: Raw feed content
            
        Returns:
            Detected format name
        """
        content = content.strip()
        
        for fmt, pattern in cls.FORMAT_PATTERNS.items():
            if re.search(pattern, content, re.MULTILINE):
                return fmt
        
        return 'unknown'
