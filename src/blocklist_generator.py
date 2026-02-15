#!/usr/bin/env python3
"""
Blocklist Generator Module
==========================
Generates blocklists in various formats for different security tools
including firewalls, web filters, and EDR/AV systems.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class BlocklistGenerator:
    """
    Generates blocklists for various security tools.
    
    Supported formats:
    - TXT (plain text, one per line)
    - CSV (with metadata)
    - JSON (structured format)
    - Firewall formats (iptables, pf, etc.)
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate(self, indicators: List[Dict[str, Any]], output_dir: str) -> Dict[str, str]:
        """
        Generate all blocklist files.
        
        Args:
            indicators: List of correlated indicators
            output_dir: Directory to save blocklists
            
        Returns:
            Dictionary mapping blocklist type to file path
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        blocklists = {}
        
        # Generate IP blocklist
        ip_blocklist = self._generate_ip_blocklist(indicators, output_path)
        if ip_blocklist:
            blocklists['ip'] = ip_blocklist
        
        # Generate domain blocklist
        domain_blocklist = self._generate_domain_blocklist(indicators, output_path)
        if domain_blocklist:
            blocklists['domain'] = domain_blocklist
        
        # Generate URL blocklist
        url_blocklist = self._generate_url_blocklist(indicators, output_path)
        if url_blocklist:
            blocklists['url'] = url_blocklist
        
        # Generate hash blocklist
        hash_blocklist = self._generate_hash_blocklist(indicators, output_path)
        if hash_blocklist:
            blocklists['hash'] = hash_blocklist
        
        # Generate combined blocklist
        combined_blocklist = self._generate_combined_blocklist(indicators, output_path)
        if combined_blocklist:
            blocklists['combined'] = combined_blocklist
        
        self.logger.info(f"Generated {len(blocklists)} blocklists in {output_dir}")
        return blocklists
    
    def _generate_ip_blocklist(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate IP blocklist in multiple formats."""
        ip_indicators = [i for i in indicators if i.get('type') == 'ip']
        
        if not ip_indicators:
            return ""
        
        # Filter high/medium priority only
        high_priority_ips = [i for i in ip_indicators 
                           if i.get('priority') in ['Critical', 'High', 'Medium']]
        
        if not high_priority_ips:
            high_priority_ips = ip_indicators
        
        filepath = output_path / "blocklist_ips.txt"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# IP Blocklist\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"# Total IPs: {len(high_priority_ips)}\n")
            f.write(f"# Priority: High/Medium only\n")
            f.write("#" + "="*50 + "\n\n")
            
            for indicator in high_priority_ips:
                f.write(f"{indicator['value']}\n")
        
        self.logger.info(f"Generated IP blocklist: {filepath}")
        return str(filepath)
    
    def _generate_domain_blocklist(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate domain blocklist."""
        domain_indicators = [i for i in indicators if i.get('type') == 'domain']
        
        if not domain_indicators:
            return ""
        
        # Filter high/medium priority
        high_priority_domains = [i for i in domain_indicators 
                                if i.get('priority') in ['Critical', 'High', 'Medium']]
        
        if not high_priority_domains:
            high_priority_domains = domain_indicators
        
        filepath = output_path / "blocklist_domains.txt"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Domain Blocklist\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"# Total Domains: {len(high_priority_domains)}\n")
            f.write("#" + "="*50 + "\n\n")
            
            for indicator in high_priority_domains:
                f.write(f"{indicator['value']}\n")
        
        self.logger.info(f"Generated domain blocklist: {filepath}")
        return str(filepath)
    
    def _generate_url_blocklist(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate URL blocklist."""
        url_indicators = [i for i in indicators if i.get('type') == 'url']
        
        if not url_indicators:
            return ""
        
        filepath = output_path / "blocklist_urls.txt"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# URL Blocklist\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"# Total URLs: {len(url_indicators)}\n")
            f.write("#" + "="*50 + "\n\n")
            
            for indicator in url_indicators:
                f.write(f"{indicator['value']}\n")
        
        self.logger.info(f"Generated URL blocklist: {filepath}")
        return str(filepath)
    
    def _generate_hash_blocklist(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate hash blocklist with metadata."""
        hash_indicators = [i for i in indicators if i.get('type') == 'hash']
        
        if not hash_indicators:
            return ""
        
        filepath = output_path / "blocklist_hashes.csv"
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['hash', 'hash_type', 'severity', 'priority', 'sources'])
            
            for indicator in hash_indicators:
                enrichment = indicator.get('enrichment', {})
                writer.writerow([
                    indicator['value'],
                    enrichment.get('hash_type', 'UNKNOWN'),
                    indicator.get('severity', 'low'),
                    indicator.get('priority', 'Low'),
                    ','.join(indicator.get('sources', ['unknown']))
                ])
        
        self.logger.info(f"Generated hash blocklist: {filepath}")
        return str(filepath)
    
    def _generate_combined_blocklist(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate combined JSON blocklist with full metadata."""
        filepath = output_path / "blocklist_combined.json"
        
        # Filter to high/medium priority only
        high_priority = [i for i in indicators 
                        if i.get('priority') in ['Critical', 'High', 'Medium']]
        
        blocklist_data = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_indicators': len(high_priority),
                'by_type': self._count_by_type(high_priority),
                'by_priority': self._count_by_priority(high_priority)
            },
            'indicators': high_priority
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(blocklist_data, f, indent=2)
        
        self.logger.info(f"Generated combined blocklist: {filepath}")
        return str(filepath)
    
    def _count_by_type(self, indicators: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count indicators by type."""
        counts = {}
        for indicator in indicators:
            ioc_type = indicator.get('type', 'unknown')
            counts[ioc_type] = counts.get(ioc_type, 0) + 1
        return counts
    
    def _count_by_priority(self, indicators: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count indicators by priority."""
        counts = {}
        for indicator in indicators:
            priority = indicator.get('priority', 'Low')
            counts[priority] = counts.get(priority, 0) + 1
        return counts
