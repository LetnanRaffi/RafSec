"""
RafSec Engine Module
=====================
Core malware analysis engine components.

Modules:
    - extractor: PE file feature extraction
    - analyzer: Heuristic and signature-based analysis
    - ml_model: Machine learning threat detection
"""

from .extractor import PEExtractor
from .analyzer import MalwareAnalyzer
from .ml_model import ThreatClassifier

__all__ = ['PEExtractor', 'MalwareAnalyzer', 'ThreatClassifier']
__version__ = '1.0.0'
