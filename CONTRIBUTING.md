# Contributing to TSUNAMI

Thank you for considering contributing to TSUNAMI. This document outlines the process for contributing code, documentation, and bug reports.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security Issues](#security-issues)

---

## Code of Conduct

All contributors are expected to uphold professional standards:
- Be respectful and constructive in all interactions
- All contributions must be for **authorized, defensive, or research purposes only**
- No contributions that introduce offensive capabilities beyond the existing white-hat scope

---

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- Redis (optional)
- Node.js 18+ (for React frontend changes)

### Local Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/tsunami.git
cd tsunami

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies (including dev tools)
pip install -r requirements.txt
pip install pre-commit pytest pytest-cov black isort flake8 bandit

# 4. Configure environment
cp .env.example .env
# Edit .env — SECRET_KEY is the only required field

# 5. Install pre-commit hooks
pre-commit install

# 6. Run tests to verify setup
python3 -m pytest tests/ -v
```

---

## Development Workflow

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/description` | `feat/shannon-v2-analysis` |
| Bug fix | `fix/description` | `fix/auth-jwt-expiry` |
| Security | `security/description` | `security/csrf-hardening` |
| Docs | `docs/description` | `docs/api-reference-update` |
| Tests | `test/description` | `test/threat-intel-coverage` |

### Commit Message Format

```
type(scope): concise description

[optional body]
[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`, `perf`

**Examples:**
```
feat(auth): Add TOTP two-factor authentication support
fix(security): Enforce SESSION_COOKIE_SECURE in production
test(modules): Add Shannon entropy edge case coverage
security(deps): Bump cryptography to 46.0.4 (CVE-2024-12797)
```

---

## Code Standards

### Python

We use [Black](https://black.readthedocs.io/) (line length 120), [isort](https://pycqa.github.io/isort/), and [flake8](https://flake8.pycqa.org/).

```bash
# Format code
black --line-length 120 .
isort .

# Lint
flake8 . --max-line-length 120

# Security static analysis
bandit -r . -x tests/,venv/

# Type checking (where applicable)
mypy dalga_web.py --ignore-missing-imports
```

Pre-commit hooks run these automatically on commit.

### Security Rules (Non-Negotiable)

- **No hardcoded secrets** — use environment variables
- **Input validation** — validate all user inputs with appropriate sanitization
- **Parameterized queries** — never construct SQL with f-strings or `%`
- **Least privilege** — new endpoints require `@login_required` unless explicitly public
- **Output encoding** — escape all user-controlled data in templates

---

## Testing

All changes must include tests. Minimum coverage target: **80%**.

```bash
# Run full test suite
python3 -m pytest tests/ -v

# With coverage report
python3 -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

# Run specific module tests
python3 -m pytest tests/test_dalga_auth.py -v

# Run security-focused tests
python3 -m pytest tests/ -k "security or auth" -v
```

### Test Guidelines

- Test file naming: `test_<module_name>.py`
- One assertion per test (ideally)
- Cover: happy path, edge cases, error scenarios
- Mock external API calls — tests must run offline
- No secrets in test files — use `os.environ.get()` or pytest fixtures

---

## Submitting Changes

### Pull Request Process

1. **Create a branch** from `main` (or `develop` for experimental features)
2. **Write tests** for all new functionality
3. **Run the full test suite** — all tests must pass
4. **Run linters** — zero flake8 errors on `E9,F63,F7,F82` rules
5. **Update `CHANGELOG.md`** — add an entry under `[Unreleased]`
6. **Submit PR** with:
   - Clear description of changes
   - Link to any related issues
   - Screenshots for UI changes
   - Notes on security implications (if any)

### PR Checklist

```
[ ] Tests added/updated for all changes
[ ] All tests pass locally (pytest)
[ ] Linting passes (black, flake8)
[ ] CHANGELOG.md updated
[ ] No hardcoded secrets introduced
[ ] .env.example updated if new env vars added
[ ] Documentation updated if needed
```

---

## Security Issues

**Do not open a public issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

---

## Questions?

Open a [GitHub Discussion](https://github.com/lydianai/tsunami/discussions) for general questions, feature ideas, or usage help.
