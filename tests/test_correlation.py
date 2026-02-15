#!/usr/bin/env python3
"""
Unit Tests for Correlation Engine Module
========================================
Tests for correlating indicators across multiple feeds.
"""

import sys
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from correlation_engine import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):
    """Test cases for Correlation Engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = CorrelationEngine()
    
    def test_single_source(self):
        """Test correlation with single source."""
        indicators = [
            {
                'value': '192.168.1.100',
                'type': 'ip',
                'severity': 'high',
                'confidence': 80,
                'source': 'feed1',
                'tags': ['malware']
            }
        ]
        
        result = self.engine.correlate(indicators)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['source_count'], 1)
        self.assertEqual(result[0]['priority'], 'High')
    
    def test_multi_source(self):
        """Test correlation with multiple sources."""
        indicators = [
            {
                'value': '192.168.1.100',
                'type': 'ip',
                'severity': 'medium',
                'confidence': 70,
                'source': 'feed1',
                'tags': ['suspicious']
            },
            {
                'value': '192.168.1.100',
                'type': 'ip',
                'severity': 'medium',
                'confidence': 75,
                'source': 'feed2',
                'tags': ['malware']
            }
        ]
        
        result = self.engine.correlate(indicators)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['source_count'], 2)
        self.assertEqual(result[0]['occurrence_count'], 2)
        self.assertIn('feed1', result[0]['sources'])
        self.assertIn('feed2', result[0]['sources'])
    
    def test_priority_assignment(self):
        """Test priority assignment based on source count."""
        # Create indicators from 5 different sources
        indicators = []
        for i in range(5):
            indicators.append({
                'value': '192.168.1.100',
                'type': 'ip',
                'severity': 'low',
                'confidence': 50,
                'source': f'feed{i+1}',
                'tags': []
            })
        
        result = self.engine.correlate(indicators)
        
        self.assertEqual(result[0]['source_count'], 5)
        self.assertEqual(result[0]['priority'], 'Critical')
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        indicators = [
            {
                'value': '192.168.1.100',
                'type': 'ip',
                'severity': 'high',
                'confidence': 90,
                'source': 'feed1',
                'tags': ['malware', 'c2']
            }
        ]
        
        result = self.engine.correlate(indicators)
        
        self.assertIn('risk_score', result[0])
        self.assertGreater(result[0]['risk_score'], 0)
        self.assertLessEqual(result[0]['risk_score'], 100)
    
    def test_statistics(self):
        """Test statistics generation."""
        indicators = [
            {'value': '192.168.1.100', 'type': 'ip', 'severity': 'high', 'source': 'feed1'},
            {'value': '192.168.1.100', 'type': 'ip', 'severity': 'high', 'source': 'feed2'},
            {'value': 'malware.com', 'type': 'domain', 'severity': 'medium', 'source': 'feed1'},
        ]
        
        correlated = self.engine.correlate(indicators)
        stats = self.engine.get_statistics(correlated)
        
        self.assertEqual(stats['total_indicators'], 2)
        self.assertEqual(stats['multi_source'], 1)
        self.assertEqual(stats['single_source'], 1)


if __name__ == '__main__':
    unittest.main()
