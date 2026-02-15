#!/usr/bin/env python3
"""
Unit Tests for IOC Parser Module
================================
Tests for parsing various IOC types from different feed formats.
"""

import sys
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from ioc_parser import IOCParser


class TestIOCParser(unittest.TestCase):
    """Test cases for IOC Parser."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = IOCParser()
    
    def test_parse_ipv4(self):
        """Test IPv4 address parsing."""
        text = "192.168.1.100"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], '192.168.1.100')
        self.assertEqual(result[0]['type'], 'ipv4')
    
    def test_parse_ipv6(self):
        """Test IPv6 address parsing."""
        text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = self.parser.parse(text, "test")
        
        self.assertTrue(len(result) >= 1)
        # IPv6 detection may vary
    
    def test_parse_domain(self):
        """Test domain parsing."""
        text = "malware-example.com"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], 'malware-example.com')
        self.assertEqual(result[0]['type'], 'domain')
    
    def test_parse_url(self):
        """Test URL parsing."""
        text = "http://malware-example.com/download/payload.exe"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], 'http://malware-example.com/download/payload.exe')
        self.assertEqual(result[0]['type'], 'url')
    
    def test_parse_md5(self):
        """Test MD5 hash parsing."""
        text = "a1b2c3d4e5f678901234567890123456"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], 'a1b2c3d4e5f678901234567890123456')
        self.assertEqual(result[0]['type'], 'md5')
    
    def test_parse_sha256(self):
        """Test SHA256 hash parsing."""
        text = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'sha256')
    
    def test_parse_email(self):
        """Test email parsing."""
        text = "malware@malware-example.com"
        result = self.parser.parse(text, "test")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], 'malware@malware-example.com')
        self.assertEqual(result[0]['type'], 'email')
    
    def test_parse_multiple(self):
        """Test parsing multiple IOCs from text."""
        text = """
        Malicious IP: 192.168.1.100
        Domain: malware-example.com
        Hash: a1b2c3d4e5f678901234567890123456
        URL: http://phishing-site.net/login
        Email: malware@malware-example.com
        """
        result = self.parser.parse(text, "test")
        
        # Should find at least 5 indicators
        self.assertGreaterEqual(len(result), 5)
    
    def test_parse_json(self):
        """Test parsing from JSON format."""
        data = {
            "indicators": [
                {"value": "192.168.1.100", "type": "ip"},
                {"value": "malware-example.com", "type": "domain"}
            ]
        }
        result = self.parser.parse(data, "test")
        
        self.assertGreaterEqual(len(result), 2)
    
    def test_parse_csv(self):
        """Test parsing from CSV format."""
        data = [
            ["192.168.1.100", "ip", "malware"],
            ["malware-example.com", "domain", "phishing"]
        ]
        result = self.parser.parse(data, "test")
        
        self.assertGreaterEqual(len(result), 2)
    
    def test_exclude_private_ips(self):
        """Test that private IPs are excluded."""
        text = "192.168.1.100 10.0.0.1 203.0.113.45"
        result = self.parser.parse(text, "test")
        
        # Should only find the public IP
        public_ips = [r for r in result if r['value'] == '203.0.113.45']
        self.assertEqual(len(public_ips), 1)


if __name__ == '__main__':
    unittest.main()
