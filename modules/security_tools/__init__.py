#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SECURITY TOOLS v5.0
    Security Testing and Analysis Tools
================================================================================

    Modules:
    - waf_checker: WAF Detection and Bypass Testing

================================================================================
"""

from .waf_checker import (
    WAFChecker,
    WAFType,
    WAFDetectionResult,
    PayloadTestResult,
    BypassSuggestion,
    check_waf,
    test_payloads,
    get_bypass_suggestions,
    get_waf_checker,
)

__all__ = [
    "WAFChecker",
    "WAFType",
    "WAFDetectionResult",
    "PayloadTestResult",
    "BypassSuggestion",
    "check_waf",
    "test_payloads",
    "get_bypass_suggestions",
    "get_waf_checker",
]
