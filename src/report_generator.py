#!/usr/bin/env python3
"""
Report Generator Module
=======================
Generates comprehensive threat intelligence reports including
summaries, statistics, and detailed indicator information.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class ReportGenerator:
    """
    Generates threat intelligence reports in multiple formats.
    
    Report types:
    - JSON (structured data)
    - HTML (visual report)
    - TXT (plain text summary)
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate(self, indicators: List[Dict[str, Any]], output_dir: str) -> str:
        """
        Generate comprehensive threat intelligence report.
        
        Args:
            indicators: List of correlated indicators
            output_dir: Directory to save report
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate JSON report
        report_path = self._generate_json_report(indicators, output_path)
        
        # Generate HTML report
        self._generate_html_report(indicators, output_path)
        
        # Generate text summary
        self._generate_text_summary(indicators, output_path)
        
        return report_path
    
    def _generate_json_report(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate JSON format report."""
        filepath = output_path / "threat_report.json"
        
        report = {
            'report_metadata': {
                'title': 'Threat Intelligence Report',
                'generated_at': datetime.utcnow().isoformat(),
                'generator': 'Threat Intelligence Aggregator v1.0',
                'internship': 'Unified Mentor - 3 Month Program'
            },
            'executive_summary': self._generate_executive_summary(indicators),
            'statistics': self._generate_statistics(indicators),
            'high_priority_indicators': self._get_high_priority(indicators),
            'all_indicators': indicators
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Generated JSON report: {filepath}")
        return str(filepath)
    
    def _generate_html_report(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate HTML format report."""
        filepath = output_path / "threat_report.html"
        
        stats = self._generate_statistics(indicators)
        high_priority = self._get_high_priority(indicators)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #1a365d;
            border-bottom: 3px solid #3182ce;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c5282;
            margin-top: 30px;
        }}
        .summary-box {{
            background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1a365d;
        }}
        .stat-label {{
            color: #4a5568;
            font-size: 0.9em;
        }}
        .priority-critical {{ color: #c53030; font-weight: bold; }}
        .priority-high {{ color: #dd6b20; font-weight: bold; }}
        .priority-medium {{ color: #d69e2e; }}
        .priority-low {{ color: #38a169; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background-color: #2c5282;
            color: white;
        }}
        tr:hover {{
            background-color: #f7fafc;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: #718096;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Threat Intelligence Report</h1>
        
        <div class="summary-box">
            <h3 style="margin-top: 0;">Executive Summary</h3>
            <p>This report contains threat intelligence indicators collected and correlated from multiple feeds.</p>
            <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Total Indicators:</strong> {stats['total_indicators']}</p>
            <p><strong>High Priority:</strong> {stats['by_priority'].get('Critical', 0) + stats['by_priority'].get('High', 0)}</p>
        </div>
        
        <h2>Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total_indicators']}</div>
                <div class="stat-label">Total Indicators</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['by_priority'].get('Critical', 0)}</div>
                <div class="stat-label">Critical Priority</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['by_priority'].get('High', 0)}</div>
                <div class="stat-label">High Priority</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['multi_source']}</div>
                <div class="stat-label">Multi-Source</div>
            </div>
        </div>
        
        <h2>Indicators by Type</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Count</th>
            </tr>
"""
        
        for ioc_type, count in stats['by_type'].items():
            html += f"""
            <tr>
                <td>{ioc_type.upper()}</td>
                <td>{count}</td>
            </tr>
"""
        
        html += f"""
        </table>
        
        <h2>High Priority Indicators</h2>
        <table>
            <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Priority</th>
                <th>Risk Score</th>
                <th>Sources</th>
            </tr>
"""
        
        for indicator in high_priority[:50]:  # Show top 50
            priority_class = f"priority-{indicator.get('priority', 'low').lower()}"
            html += f"""
            <tr>
                <td>{indicator['value'][:80]}{'...' if len(indicator['value']) > 80 else ''}</td>
                <td>{indicator.get('type', 'unknown').upper()}</td>
                <td class="{priority_class}">{indicator.get('priority', 'Low')}</td>
                <td>{indicator.get('risk_score', 0)}</td>
                <td>{len(indicator.get('sources', []))}</td>
            </tr>
"""
        
        html += f"""
        </table>
        
        <div class="footer">
            <p>Generated by Threat Intelligence Aggregator</p>
            <p>Unified Mentor Internship Program</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"Generated HTML report: {filepath}")
        return str(filepath)
    
    def _generate_text_summary(self, indicators: List[Dict[str, Any]], output_path: Path) -> str:
        """Generate plain text summary."""
        filepath = output_path / "summary.txt"
        
        stats = self._generate_statistics(indicators)
        high_priority = self._get_high_priority(indicators)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("THREAT INTELLIGENCE REPORT - SUMMARY\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Internship: Unified Mentor - 3 Month Program\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Indicators: {stats['total_indicators']}\n")
            f.write(f"Critical Priority: {stats['by_priority'].get('Critical', 0)}\n")
            f.write(f"High Priority: {stats['by_priority'].get('High', 0)}\n")
            f.write(f"Medium Priority: {stats['by_priority'].get('Medium', 0)}\n")
            f.write(f"Low Priority: {stats['by_priority'].get('Low', 0)}\n")
            f.write(f"Multi-Source Indicators: {stats['multi_source']}\n\n")
            
            f.write("INDICATORS BY TYPE\n")
            f.write("-"*40 + "\n")
            for ioc_type, count in stats['by_type'].items():
                f.write(f"  {ioc_type.upper()}: {count}\n")
            f.write("\n")
            
            f.write("TOP 20 HIGH PRIORITY INDICATORS\n")
            f.write("-"*40 + "\n")
            for i, indicator in enumerate(high_priority[:20], 1):
                f.write(f"{i}. [{indicator.get('priority', 'Low')}] {indicator['value']}\n")
                f.write(f"   Type: {indicator.get('type', 'unknown')}, ")
                f.write(f"Risk: {indicator.get('risk_score', 0)}, ")
                f.write(f"Sources: {len(indicator.get('sources', []))}\n\n")
        
        self.logger.info(f"Generated text summary: {filepath}")
        return str(filepath)
    
    def _generate_executive_summary(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary."""
        stats = self._generate_statistics(indicators)
        high_priority = self._get_high_priority(indicators)
        
        return {
            'total_indicators': stats['total_indicators'],
            'critical_count': stats['by_priority'].get('Critical', 0),
            'high_count': stats['by_priority'].get('High', 0),
            'medium_count': stats['by_priority'].get('Medium', 0),
            'low_count': stats['by_priority'].get('Low', 0),
            'multi_source_count': stats['multi_source'],
            'avg_risk_score': stats['avg_risk_score'],
            'top_threats': [i['value'] for i in high_priority[:10]]
        }
    
    def _generate_statistics(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        stats = {
            'total_indicators': len(indicators),
            'by_type': {},
            'by_priority': {},
            'by_severity': {},
            'multi_source': 0,
            'single_source': 0,
            'avg_sources': 0,
            'avg_risk_score': 0,
            'avg_confidence': 0
        }
        
        total_sources = 0
        total_risk = 0
        total_confidence = 0
        
        for indicator in indicators:
            # By type
            ioc_type = indicator.get('type', 'unknown')
            stats['by_type'][ioc_type] = stats['by_type'].get(ioc_type, 0) + 1
            
            # By priority
            priority = indicator.get('priority', 'Low')
            stats['by_priority'][priority] = stats['by_priority'].get(priority, 0) + 1
            
            # By severity
            severity = indicator.get('severity', 'low')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Source count
            source_count = indicator.get('source_count', 1)
            if source_count > 1:
                stats['multi_source'] += 1
            else:
                stats['single_source'] += 1
            
            total_sources += source_count
            total_risk += indicator.get('risk_score', 0)
            total_confidence += indicator.get('confidence', 0)
        
        if indicators:
            stats['avg_sources'] = round(total_sources / len(indicators), 2)
            stats['avg_risk_score'] = round(total_risk / len(indicators), 2)
            stats['avg_confidence'] = round(total_confidence / len(indicators), 2)
        
        return stats
    
    def _get_high_priority(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get high priority indicators sorted by risk score."""
        high_priority = [i for i in indicators 
                        if i.get('priority') in ['Critical', 'High']]
        return sorted(high_priority, key=lambda x: x.get('risk_score', 0), reverse=True)
