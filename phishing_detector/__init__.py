"""Phishing URL Detector: heuristic feature extraction and scoring for URLs."""

from .detector import Result, analyze
from .features import UrlFeatures, extract_features

__all__ = ["analyze", "extract_features", "Result", "UrlFeatures"]
__version__ = "1.0.0"
