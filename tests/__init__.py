#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Test Suite
==================

Comprehensive test suite for TSUNAMI cybersecurity platform.

Test Categories:
- test_validation.py: Input validation, SQL injection, XSS prevention
- test_security_comprehensive.py: Password hashing, rate limiting, audit logging
- test_api.py: API endpoint tests, authentication, error handling
- test_sigint.py: WiFi, Bluetooth, cell tower scanning modules

Usage:
    # Run all tests
    pytest tests/ -v

    # Run with coverage
    pytest tests/ -v --cov=. --cov-report=html

    # Run specific category
    pytest tests/ -v -m security
    pytest tests/ -v -m api
    pytest tests/ -v -m osint

    # Run with parallel execution
    pytest tests/ -v -n auto

    # Run property-based tests only
    pytest tests/ -v -k "PropertyBased"
"""

import sys
from pathlib import Path

# Ensure parent directory is in path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
