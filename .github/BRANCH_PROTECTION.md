# Branch Protection Rules for TSUNAMI

This document describes the branch protection configuration for the TSUNAMI repository.

## Protected Branches

### `main` (Production Branch)

The `main` branch is the production branch and is fully protected.

**Required Settings:**

| Rule | Setting |
|------|---------|
| Require pull request reviews before merging | ✅ Enabled |
| Required number of approvals | 1 |
| Dismiss stale reviews when new commits are pushed | ✅ Enabled |
| Require review from code owners | ✅ Enabled (CODEOWNERS) |
| Require status checks to pass before merging | ✅ Enabled |
| Require branches to be up to date before merging | ✅ Enabled |
| Require signed commits | ✅ Recommended |
| Include administrators | ✅ Enabled |
| Allow force pushes | ❌ Disabled |
| Allow deletions | ❌ Disabled |

**Required Status Checks:**
- `ci / test` (Python tests)
- `ci / lint` (Code quality)
- `ci / security-scan` (Trivy + TruffleHog)
- `ci / docker-build` (Docker build validation)

### `develop` (Development Branch)

| Rule | Setting |
|------|---------|
| Require pull request reviews | ✅ Enabled |
| Required approvals | 1 |
| Require status checks | ✅ Enabled |
| Allow force pushes | ❌ Disabled |

## Branch Naming Conventions

| Branch Type | Pattern | Example |
|-------------|---------|---------|
| Feature | `feature/description` | `feature/threat-correlation` |
| Bug Fix | `fix/description` | `fix/auth-token-expiry` |
| Security | `security/description` | `security/cve-2024-1234` |
| Documentation | `docs/description` | `docs/api-reference` |
| Release | `release/version` | `release/v6.1.0` |
| Hotfix | `hotfix/description` | `hotfix/critical-auth-bypass` |

## Configuring Branch Protection via GitHub UI

1. Navigate to your repository on GitHub
2. Go to **Settings** → **Branches**
3. Click **Add branch protection rule**
4. Set the branch name pattern (e.g., `main`)
5. Configure the rules as described above
6. Click **Create**

## Configuring via GitHub CLI

```bash
# Protect main branch
gh api repos/lydianai/tsunami/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["ci / test","ci / lint","ci / security-scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true,"require_code_owner_reviews":true}' \
  --field restrictions=null
```

## Security-Critical Branch Rules

For the `main` branch, the following additional security measures apply:

1. **No direct pushes**: All changes must go through pull requests
2. **Mandatory security scan**: TruffleHog secret scanning must pass before any merge
3. **Dependency audit**: Security vulnerabilities in dependencies will block merges
4. **Review for sensitive files**: Changes to `SECURITY.md`, `.github/workflows/`, `config/` require mandatory code owner review

## Release Process

1. Create a release branch: `git checkout -b release/v6.1.0`
2. Update version references and CHANGELOG.md
3. Create a pull request from release branch to `main`
4. Ensure all CI checks pass
5. Merge via "Create a merge commit" (not squash)
6. Tag the release: `git tag -s v6.1.0 -m "Release v6.1.0"`
7. Push the tag: `git push origin v6.1.0`
8. Create a GitHub Release from the tag

## Hotfix Process

For critical security fixes:

1. Branch from `main`: `git checkout -b hotfix/description main`
2. Apply the minimal required fix
3. Create pull request directly to `main` with `[HOTFIX]` label
4. Expedited review process applies (1 reviewer minimum)
5. Merge and immediately tag: `v6.0.x`
6. Backport to `develop` if applicable
