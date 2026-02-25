# Contributing to TSUNAMI

Thank you for your interest in contributing to TSUNAMI! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Submitting Changes](#submitting-changes)

---

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, inclusive, and collaborative.

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Redis (optional — falls back to in-memory)
- Node.js 18+ (for React frontend)

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/lydianai/tsunami.git
cd tsunami

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Copy environment template
cp .env.example .env
# Edit .env with your configuration
```

### Running the Development Server

```bash
# Backend (Flask)
python3 dalga_web.py
# → http://localhost:8082

# Frontend (React - optional)
cd tsunam-react
npm install
npm start
# → http://localhost:3001

# Docker (full stack)
docker-compose up -d
# → http://localhost:8080
```

---

## Development Workflow

### Branch Strategy

- `main` — Production-ready code
- `develop` — Integration branch for features
- `feature/*` — New features
- `bugfix/*` — Bug fixes
- `hotfix/*` — Critical production fixes

### Creating a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b bugfix/your-bugfix-name
```

### Making Changes

1. Write clear, concise commit messages
2. Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Code style changes (formatting, etc.)
   - `refactor:` Code refactoring
   - `test:` Adding or updating tests
   - `chore:` Maintenance tasks
   - `security:` Security-related changes

Example:
```
feat(osint): add Shodan API integration for IoT device discovery

- Implemented Shodan search endpoint
- Added API key validation
- Included unit tests with 95% coverage
- Updated API documentation
```

---

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://pep8.org/) style guide
- Use [Black](https://black.readthedocs.io/) for formatting (line length: 120)
- Use [flake8](https://flake8.pycqa.org/) for linting
- Type hints required for all functions
- Docstrings required for all modules, classes, and public functions

### Formatting

```bash
# Format code
black --line-length 120 .

# Check linting
flake8 . --max-line-length=120

# Sort imports
isort .
```

### Naming Conventions

- `snake_case` for variables and functions
- `PascalCase` for classes
- `UPPER_CASE` for constants
- `_leading_underscore` for private/internal functions

### Example Code Structure

```python
"""
OSINT module for IP and domain intelligence.

This module provides functions for gathering open source intelligence
on IP addresses and domain names using various APIs and databases.
"""

from typing import Dict, List, Optional
from flask import jsonify, request

from dalga_auth import login_required


def query_ip_intelligence(ip_address: str) -> Dict[str, any]:
    """
    Query intelligence data for an IP address.

    Args:
        ip_address: The IP address to query

    Returns:
        Dictionary containing intelligence data including geolocation,
        WHOIS information, and threat intelligence feeds.

    Raises:
        ValueError: If IP address is invalid
        APIError: If external API call fails
    """
    # Implementation here
    pass


@app.route('/api/osint/ip', methods=['POST'])
@login_required
def osint_ip_query():
    """
    API endpoint for IP intelligence queries.

    Requires authentication. Returns comprehensive OSINT data.
    """
    data = request.get_json()
    ip_address = data.get('ip_address')

    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400

    try:
        result = query_ip_intelligence(ip_address)
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
```

---

## Testing Guidelines

### Test Structure

```
tests/
├── test_dalga_auth.py
├── test_dalga_osint.py
├── test_dalga_geo.py
├── test_dalga_security.py
└── test_modules/
    ├── test_shannon.py
    ├── test_honeypot.py
    └── test_mitre_attack.py
```

### Writing Tests

- Use [pytest](https://docs.pytest.org/)
- Aim for 80%+ code coverage
- Test both success and failure paths
- Mock external API calls
- Use descriptive test names

### Example Test

```python
"""
Tests for OSINT module functionality.
"""

import pytest
from unittest.mock import patch, MagicMock
from dalga_osint import query_ip_intelligence, validate_ip_address


class TestIPAddressValidation:
    """Test IP address validation logic."""

    def test_valid_ipv4(self):
        """Test that valid IPv4 addresses pass validation."""
        assert validate_ip_address('192.168.1.1') is True
        assert validate_ip_address('8.8.8.8') is True

    def test_invalid_ipv4(self):
        """Test that invalid IPv4 addresses fail validation."""
        assert validate_ip_address('256.256.256.256') is False
        assert validate_ip_address('invalid') is False


class TestIPIntelligence:
    """Test IP intelligence gathering."""

    @patch('dalga_osint.requests.get')
    def test_query_ip_success(self, mock_get):
        """Test successful IP intelligence query."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'country': 'US',
            'city': 'Mountain View',
            'org': 'AS15169 Google LLC'
        }
        mock_get.return_value = mock_response

        result = query_ip_intelligence('8.8.8.8')

        assert result['country'] == 'US'
        assert result['org'] == 'AS15169 Google LLC'

    def test_query_ip_invalid_address(self):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError):
            query_ip_intelligence('invalid-ip')
```

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html

# Run specific test file
python3 -m pytest tests/test_dalga_osint.py -v

# Run specific test
python3 -m pytest tests/test_dalga_osint.py::TestIPAddressValidation::test_valid_ipv4 -v
```

---

## Security Considerations

### NEVER Commit

- API keys or secrets
- Passwords or credentials
- Private keys (SSH, GPG, etc.)
- Personal access tokens
- Database connection strings with passwords

### Validated Inputs

- All user inputs MUST be validated
- Use parameterized queries to prevent SQL injection
- Sanitize output to prevent XSS
- Implement rate limiting on public endpoints

### Dependencies

- Keep dependencies up to date (Dependabot will help)
- Review security advisories
- Run `pip-audit` and `safety check` regularly

```bash
pip-audit
safety check --full-report
```

---

## Submitting Changes

### Before Submitting

- [ ] All tests pass (`python3 -m pytest tests/ -v`)
- [ ] Code coverage is 80%+ (`pytest --cov`)
- [ ] Code formatted (`black --line-length 120 .`)
- [ ] No linting errors (`flake8`)
- [ ] Pre-commit hooks pass
- [ ] Documentation updated
- [ ] Commit messages follow conventions

### Creating a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Go to https://github.com/lydianai/tsunami and click "Compare & pull request"

3. Fill in the PR template:
   - Summarize your changes
   - List related issues
   - Add screenshots if applicable
   - Confirm all checkboxes

4. Request review from maintainers

### Pull Request Review Process

- Automated checks must pass (CI/CD)
- At least one maintainer approval required
- Address all review comments
- Keep PRs focused and reasonably sized

### After Merge

- Delete your branch (after merge)
- Update your local repository:
  ```bash
  git checkout main
  git pull upstream main
  ```

---

## Getting Help

- **Documentation:** Check [README.md](README.md) and [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- **Issues:** Search or create [GitHub Issues](https://github.com/lydianai/tsunami/issues)
- **Discussions:** Ask questions in [GitHub Discussions](https://github.com/lydianai/tsunami/discussions)
- **Security:** Report vulnerabilities via [SECURITY.md](SECURITY.md)

---

## Recognition

Contributors who make significant contributions will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Eligible for collaborator access

Thank you for contributing to TSUNAMI! 🌊
