#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[release]${NC} $1"; }
warn() { echo -e "${YELLOW}[release]${NC} $1"; }
err()  { echo -e "${RED}[release]${NC} $1"; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

git diff --quiet || err "Working tree is dirty — commit or stash changes first."

LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
log "Latest tag: $LATEST_TAG"

CURRENT_VERSION=$(grep -E '^version\s*=' pyproject.toml | head -1 | sed 's/version\s*=\s*"\([^"]*\)"/\1/')
log "Current version in pyproject.toml: $CURRENT_VERSION"

echo ""
read -r -p "Enter new version (e.g. 0.1.9): " NEW_VERSION

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    err "Invalid version format — use X.Y.Z (e.g. 0.1.9)"
fi

TAG="v${NEW_VERSION}"

if git rev-parse "$TAG" >/dev/null 2>&1; then
    err "Tag $TAG already exists."
fi

# --- Apply version bumps across all files ---

sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml
sed -i "s/VERSION = \"v$CURRENT_VERSION\"/VERSION = \"v$NEW_VERSION\"/" pythonbpf/codegen.py
sed -i "s/release = \"$CURRENT_VERSION\"/release = \"$NEW_VERSION\"/" docs/conf.py
sed -i "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" docs/conf.py

log "Bumped version $CURRENT_VERSION → $NEW_VERSION in:"
log "  pyproject.toml"
log "  pythonbpf/codegen.py"
log "  docs/conf.py"

# --- Show diff and confirm ---

echo ""
log "Changes to be committed:"
git diff --stat
echo ""
git diff

echo ""
read -r -p "Commit these changes and create tag $TAG? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    git checkout -- pyproject.toml pythonbpf/codegen.py docs/conf.py
    warn "Reverted changes. Aborted."
    exit 0
fi

git add pyproject.toml pythonbpf/codegen.py docs/conf.py
git commit -m "Bump version to $NEW_VERSION"
log "Committed version bump."

git tag "$TAG"
log "Created tag $TAG."

echo ""
read -r -p "Push commit and tag to origin? [y/N]: " PUSH
if [[ "$PUSH" =~ ^[Yy]$ ]]; then
    git push origin HEAD
    git push origin "$TAG"
    log "Pushed commit and tag $TAG. CI will build and publish to PyPI."
else
    warn "Push skipped. Run: git push origin HEAD && git push origin $TAG"
fi
