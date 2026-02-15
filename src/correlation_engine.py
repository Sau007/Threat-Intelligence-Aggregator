#!/usr/bin/env python3
"""
Correlation Engine Module
=========================
Identifies repeated indicators across multiple feeds and
assigns priority scores based on frequency and severity.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Set


class CorrelationEngine:
    """
    Correlates IOCs across multiple threat intelligence feeds.
    
    Features:
    - Detects repeated indicators
    - Assigns priority based on frequency
    - Aggregates sources and tags
    - Calculates risk scores
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Priority thresholds based on feed count
        self.priority_thresholds = {
            'critical': 5,  # 5+ feeds
            'high': 3,      # 3-4 feeds
            'medium': 2,    # 2 feeds
            'low': 1        # Single feed
        }
    
    def correlate(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate indicators across feeds.
        
        Args:
            indicators: List of normalized indicators
            
        Returns:
            List of correlated indicators with priority scores
        """
        self.logger.info(f"Correlating {len(indicators)} indicators")
        
        # Group indicators by value
        grouped = self._group_by_value(indicators)
        
        # Merge grouped indicators
        correlated = []
        for value, group in grouped.items():
            merged = self._merge_indicators(group)
            if merged:
                correlated.append(merged)
        
        # Sort by priority (highest first)
        correlated.sort(key=lambda x: self._priority_sort_key(x), reverse=True)
        
        self.logger.info(f"Correlation complete: {len(correlated)} unique indicators")
        return correlated
    
    def _group_by_value(self, indicators: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group indicators by their value."""
        grouped = defaultdict(list)
        
        for indicator in indicators:
            value = indicator.get('value', '').lower()
            if value:
                grouped[value].append(indicator)
        
        return grouped
    
    def _merge_indicators(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple occurrences of the same indicator."""
        if not group:
            return {}
        
        # Use the first indicator as base
        base = group[0].copy()
        
        # Collect all sources
        all_sources: Set[str] = set()
        all_tags: Set[str] = set()
        severities: List[str] = []
        confidences: List[int] = []
        
        for indicator in group:
            # Collect sources
            source = indicator.get('source', 'unknown')
            all_sources.add(source)
            
            # Collect tags
            tags = indicator.get('tags', [])
            all_tags.update(tags)
            
            # Collect severities
            severity = indicator.get('severity', 'low')
            severities.append(severity)
            
            # Collect confidences
            confidence = indicator.get('confidence', 50)
            confidences.append(confidence)
        
        # Update merged indicator
        base['sources'] = sorted(list(all_sources))
        base['source_count'] = len(all_sources)
        base['tags'] = sorted(list(all_tags))
        base['occurrence_count'] = len(group)
        
        # Determine overall severity
        base['severity'] = self._determine_overall_severity(severities)
        
        # Calculate average confidence
        base['confidence'] = sum(confidences) // len(confidences) if confidences else 50
        
        # Assign priority based on frequency and severity
        base['priority'] = self._assign_priority(base)
        
        # Calculate risk score
        base['risk_score'] = self._calculate_risk_score(base)
        
        # Update metadata
        base['metadata']['correlated'] = True
        base['metadata']['correlation_count'] = len(group)
        
        return base
    
    def _determine_overall_severity(self, severities: List[str]) -> str:
        """Determine the overall severity from multiple indicators."""
        if 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'
    
    def _assign_priority(self, indicator: Dict[str, Any]) -> str:
        """Assign priority based on source count and severity."""
        source_count = indicator.get('source_count', 1)
        severity = indicator.get('severity', 'low')
        
        # Critical: 5+ sources OR high severity with 3+ sources
        if source_count >= self.priority_thresholds['critical']:
            return 'Critical'
        
        if severity == 'high' and source_count >= self.priority_thresholds['high']:
            return 'Critical'
        
        # High: 3-4 sources OR high severity
        if source_count >= self.priority_thresholds['high']:
            return 'High'
        
        if severity == 'high':
            return 'High'
        
        # Medium: 2 sources OR medium severity
        if source_count >= self.priority_thresholds['medium']:
            return 'Medium'
        
        if severity == 'medium':
            return 'Medium'
        
        # Low: everything else
        return 'Low'
    
    def _calculate_risk_score(self, indicator: Dict[str, Any]) -> int:
        """
        Calculate a risk score (0-100) based on multiple factors.
        
        Factors:
        - Source count (more sources = higher risk)
        - Severity (high severity = higher risk)
        - Confidence (higher confidence = higher risk)
        """
        score = 0
        
        # Base score from source count (max 40 points)
        source_count = indicator.get('source_count', 1)
        score += min(40, source_count * 8)
        
        # Severity bonus (max 30 points)
        severity_scores = {'high': 30, 'medium': 20, 'low': 10}
        severity = indicator.get('severity', 'low')
        score += severity_scores.get(severity, 0)
        
        # Confidence factor (max 30 points)
        confidence = indicator.get('confidence', 50)
        score += int(confidence * 0.3)
        
        return min(100, score)
    
    def _priority_sort_key(self, indicator: Dict[str, Any]) -> tuple:
        """Generate sort key for priority ordering."""
        priority_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        priority = indicator.get('priority', 'Low')
        risk_score = indicator.get('risk_score', 0)
        source_count = indicator.get('source_count', 0)
        
        return (priority_order.get(priority, 0), risk_score, source_count)
    
    def get_statistics(self, correlated: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate correlation statistics.
        
        Args:
            correlated: List of correlated indicators
            
        Returns:
            Dictionary with correlation statistics
        """
        stats = {
            'total_indicators': len(correlated),
            'by_priority': defaultdict(int),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'multi_source': 0,
            'single_source': 0,
            'avg_sources': 0,
            'avg_risk_score': 0
        }
        
        total_sources = 0
        total_risk = 0
        
        for indicator in correlated:
            priority = indicator.get('priority', 'Low')
            ioc_type = indicator.get('type', 'unknown')
            severity = indicator.get('severity', 'low')
            source_count = indicator.get('source_count', 1)
            risk_score = indicator.get('risk_score', 0)
            
            stats['by_priority'][priority] += 1
            stats['by_type'][ioc_type] += 1
            stats['by_severity'][severity] += 1
            
            if source_count > 1:
                stats['multi_source'] += 1
            else:
                stats['single_source'] += 1
            
            total_sources += source_count
            total_risk += risk_score
        
        if correlated:
            stats['avg_sources'] = round(total_sources / len(correlated), 2)
            stats['avg_risk_score'] = round(total_risk / len(correlated), 2)
        
        # Convert defaultdicts to regular dicts for JSON serialization
        stats['by_priority'] = dict(stats['by_priority'])
        stats['by_type'] = dict(stats['by_type'])
        stats['by_severity'] = dict(stats['by_severity'])
        
        return stats
