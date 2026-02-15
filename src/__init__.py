#!/usr/bin/env python3
"""
Threat Intelligence Aggregator
==============================

A comprehensive tool to collect, parse, normalize, and correlate 
threat intelligence indicators from multiple feeds.

Modules:
    main: Main orchestrator and CLI entry point
    feed_loader: Loads IOC feeds from files and URLs
    ioc_parser: Parses various IOC types (IPs, domains, URLs, hashes)
    normalizer: Normalizes indicators into unified format
    correlation_engine: Correlates indicators across feeds
    blocklist_generator: Generates blocklists for security tools
    report_generator: Creates comprehensive threat reports
    utils: Utility functions and helpers
"""


from .main import ThreatIntelligenceAggregator
from .feed_loader import FeedLoader
from .ioc_parser import IOCParser
from .normalizer import DataNormalizer
from .correlation_engine import CorrelationEngine
from .blocklist_generator import BlocklistGenerator
from .report_generator import ReportGenerator

__all__ = [
    'ThreatIntelligenceAggregator',
    'FeedLoader',
    'IOCParser',
    'DataNormalizer',
    'CorrelationEngine',
    'BlocklistGenerator',
    'ReportGenerator',
]
