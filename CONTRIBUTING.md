# Contributing to TSUNAMI

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Code Style

- Python: Black (line-length 120), isort, flake8
- Run formatters before committing:

```bash
black --line-length 120 .
isort .
flake8 .
```

## Testing

All changes must include tests. Target: 80%+ coverage.

```bash
# Run tests
python3 -m pytest tests/ -v

# With coverage
python3 -m pytest tests/ --cov=. --cov-report=term-missing
```

## Commit Messages

Format: `type(scope): description`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`

Examples:
- `feat(auth): Add 2FA TOTP support`
- `fix(security): Make SESSION_COOKIE_SECURE environment-aware`
- `test(modules): Add Shannon entropy unit tests`

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass (`pytest`)
4. Run linters (`black`, `isort`, `flake8`)
5. Update CHANGELOG.md
6. Submit PR with clear description

## Security

Report security vulnerabilities privately. Do not open public issues for security bugs.
