"""
Shannon AI Pentester - TSUNAMI Bridge Module
=============================================
Autonomous AI pentesting integration with TSUNAMI platform.

Components:
- ShannonManager: CLI wrapper for Shannon execution
- ShannonFinding: Parsed vulnerability findings
- ShannonSOARConnector: SOAR incident integration
- ShannonMapVisualizer: Map marker generation
"""

from .shannon_manager import ShannonManager, ShannonSession
from .result_parser import ShannonFinding, Severity, parse_shannon_report
from .soar_connector import ShannonSOARConnector
from .map_visualizer import ShannonMapVisualizer

__version__ = "1.0.0"
__all__ = [
    "ShannonManager",
    "ShannonSession",
    "ShannonFinding",
    "Severity",
    "parse_shannon_report",
    "ShannonSOARConnector",
    "ShannonMapVisualizer"
]
