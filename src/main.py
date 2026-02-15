#!/usr/bin/env python3
"""
Threat Intelligence Aggregator
==============================
A comprehensive tool to collect, parse, normalize, and correlate 
threat intelligence indicators from multiple feeds.

Internship: Unified Mentor
Duration: 3 Months (Project provided in 2 months)
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from feed_loader import FeedLoader
from ioc_parser import IOCParser
from normalizer import DataNormalizer
from correlation_engine import CorrelationEngine
from blocklist_generator import BlocklistGenerator
from report_generator import ReportGenerator
from utils import setup_logging, load_config


class ThreatIntelligenceAggregator:
    """
    Main orchestrator class for the Threat Intelligence Aggregator.
    
    This class coordinates the entire workflow from loading feeds
to generating final reports and blocklists.
    """
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize the aggregator with configuration.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.feed_loader = FeedLoader()
        self.ioc_parser = IOCParser()
        self.normalizer = DataNormalizer()
        self.correlation_engine = CorrelationEngine()
        self.blocklist_generator = BlocklistGenerator()
        self.report_generator = ReportGenerator()
        
        # Storage for processed data
        self.raw_indicators: List[Dict[str, Any]] = []
        self.normalized_indicators: List[Dict[str, Any]] = []
        self.correlated_indicators: List[Dict[str, Any]] = []
        
        self.logger.info("Threat Intelligence Aggregator initialized")
    
    def run(self, feed_sources: List[str], output_dir: str = "output") -> Dict[str, Any]:
        """
        Execute the complete aggregation workflow.
        
        Args:
            feed_sources: List of feed URLs or file paths
            output_dir: Directory for output files
            
        Returns:
            Dictionary containing summary of processed data
        """
        start_time = datetime.now()
        self.logger.info(f"Starting aggregation workflow at {start_time}")
        
        # Step 1: Load feeds
        self.logger.info("Step 1: Loading IOC feeds...")
        raw_feeds = self._load_feeds(feed_sources)
        
        # Step 2: Parse indicators
        self.logger.info("Step 2: Parsing indicators...")
        self.raw_indicators = self._parse_indicators(raw_feeds)
        
        # Step 3: Normalize data
        self.logger.info("Step 3: Normalizing data...")
        self.normalized_indicators = self._normalize_data(self.raw_indicators)
        
        # Step 4: Correlate indicators
        self.logger.info("Step 4: Correlating indicators...")
        self.correlated_indicators = self._correlate_indicators(self.normalized_indicators)
        
        # Step 5: Generate blocklists
        self.logger.info("Step 5: Generating blocklists...")
        blocklists = self._generate_blocklists(self.correlated_indicators, output_dir)
        
        # Step 6: Generate report
        self.logger.info("Step 6: Generating final report...")
        report_path = self._generate_report(self.correlated_indicators, output_dir)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "feeds_processed": len(feed_sources),
            "total_raw_indicators": len(self.raw_indicators),
            "total_normalized_indicators": len(self.normalized_indicators),
            "total_correlated_indicators": len(self.correlated_indicators),
            "high_priority_indicators": len([i for i in self.correlated_indicators if i.get("priority") == "High"]),
            "blocklists_generated": list(blocklists.keys()),
            "report_path": report_path
        }
        
        self.logger.info(f"Aggregation workflow completed in {duration:.2f} seconds")
        self.logger.info(f"Summary: {summary}")
        
        return summary
    
    def _load_feeds(self, feed_sources: List[str]) -> List[Dict[str, Any]]:
        """Load IOC feeds from sources."""
        raw_feeds = []
        for source in feed_sources:
            try:
                feed_data = self.feed_loader.load(source)
                raw_feeds.append({
                    "source": source,
                    "data": feed_data
                })
                self.logger.info(f"Loaded feed from {source}")
            except Exception as e:
                self.logger.error(f"Failed to load feed from {source}: {e}")
        return raw_feeds
    
    def _parse_indicators(self, raw_feeds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse indicators from raw feeds."""
        indicators = []
        for feed in raw_feeds:
            try:
                parsed = self.ioc_parser.parse(feed["data"], feed["source"])
                indicators.extend(parsed)
            except Exception as e:
                self.logger.error(f"Failed to parse feed {feed['source']}: {e}")
        return indicators
    
    def _normalize_data(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize parsed indicators."""
        normalized = []
        for indicator in indicators:
            try:
                norm = self.normalizer.normalize(indicator)
                if norm:
                    normalized.append(norm)
            except Exception as e:
                self.logger.warning(f"Failed to normalize indicator: {e}")
        return normalized
    
    def _correlate_indicators(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate indicators across feeds."""
        return self.correlation_engine.correlate(indicators)
    
    def _generate_blocklists(self, indicators: List[Dict[str, Any]], output_dir: str) -> Dict[str, str]:
        """Generate blocklists for different categories."""
        return self.blocklist_generator.generate(indicators, output_dir)
    
    def _generate_report(self, indicators: List[Dict[str, Any]], output_dir: str) -> str:
        """Generate final threat intelligence report."""
        return self.report_generator.generate(indicators, output_dir)


def main():
    """Main entry point for the Threat Intelligence Aggregator."""
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator - Collect and correlate IOCs from multiple feeds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process feeds from URLs
  python main.py --feeds https://example.com/feed1.txt https://example.com/feed2.csv
  
  # Process local feed files
  python main.py --feeds data/feed1.txt data/feed2.json
  
  # Specify custom output directory
  python main.py --feeds feeds.txt --output results/
  
  # Use configuration file
  python main.py --config config.json --feeds feeds.txt
        """
    )
    
    parser.add_argument(
        "--feeds", "-f",
        nargs="+",
        required=True,
        help="List of feed URLs or file paths to process"
    )
    
    parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory for reports and blocklists (default: output)"
    )
    
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level)
    
    # Create output directory
    Path(args.output).mkdir(parents=True, exist_ok=True)
    
    # Initialize and run aggregator
    aggregator = ThreatIntelligenceAggregator(config_path=args.config)
    
    try:
        summary = aggregator.run(
            feed_sources=args.feeds,
            output_dir=args.output
        )
        
        # Print summary
        print("\n" + "="*60)
        print("THREAT INTELLIGENCE AGGREGATION COMPLETE")
        print("="*60)
        print(f"\nFeeds Processed: {summary['feeds_processed']}")
        print(f"Total Raw Indicators: {summary['total_raw_indicators']}")
        print(f"Total Normalized Indicators: {summary['total_normalized_indicators']}")
        print(f"Total Correlated Indicators: {summary['total_correlated_indicators']}")
        print(f"High Priority Indicators: {summary['high_priority_indicators']}")
        print(f"\nBlocklists Generated:")
        for blocklist_type in summary['blocklists_generated']:
            print(f"  - {blocklist_type}")
        print(f"\nReport saved to: {summary['report_path']}")
        print(f"\nDuration: {summary['duration_seconds']:.2f} seconds")
        print("="*60)
        
    except Exception as e:
        logging.error(f"Aggregation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
