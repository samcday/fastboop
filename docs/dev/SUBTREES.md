# Git Subtree Management

fastboop uses **git subtrees** to vendor dependencies during active development sprints, enabling rapid cross-repository iteration while maintaining the ability to cleanly upstream changes back to canonical repos.

---

## Architecture

### Two-Level Subtree Structure

**Level 1: erofs-rs → gibblox**
- gibblox canonical repo vendors erofs-rs as a subtree at `gibblox/erofs-rs/`
- gibblox can iterate on erofs-rs changes during development
- Changes are split back to canonical erofs-rs when gibblox stabilizes

**Level 2: gibblox + smoo → fastboop**
- fastboop vendors both gibblox and smoo as independent top-level subtrees
- fastboop can make changes across all vendored repos in a single sprint
- Changes are split back to canonical repos when fastboop stabilizes
- gibblox maintainer then handles the erofs-rs → gibblox split separately

### Why This Approach?

1. **Each repo makes sense independently** - All canonical repos (fastboop, gibblox, smoo, erofs-rs) can be cloned and built standalone
2. **Clear ownership boundaries** - gibblox owns the erofs-rs relationship; fastboop owns gibblox + smoo
3. **Flexible development** - Make commits touching any combination of repos without worrying about boundaries during development
4. **Clean upstream flow** - Split operations are simple and follow the actual dependency graph

---

## Current Subtree State

```
fastboop/
├── gibblox/          (subtree → github.com/samcday/gibblox.git)
│   └── erofs-rs/     (subtree in gibblox canonical repo → github.com/samcday/erofs-rs.git)
└── smoo/             (subtree → github.com/samcday/smoo.git)
```

**Important:** `gibblox/erofs-rs/` is NOT a subtree in fastboop. It's part of the gibblox subtree content. Only gibblox canonical repo manages the erofs-rs subtree relationship.

---

## Daily Development Workflow

### Making Changes

**You don't need to worry about subtree boundaries during development!**

Just code normally:
- Edit files in `gibblox/`, `smoo/`, or `fastboop/` code
- Make commits touching any combination of paths
- Refactor across boundaries freely
- `git subtree split` will handle extracting the relevant changes later

Example commit touching multiple subtrees:
```bash
# This is perfectly fine!
git add cli/src/main.rs gibblox/crates/gibblox-core/src/lib.rs smoo/crates/smoo-host-core/src/lib.rs
git commit -m "Integrate new gibblox API with smoo and fastboop CLI"
```

When you split this commit later:
- It will appear in the gibblox split (with only `crates/gibblox-core/src/lib.rs` changes)
- It will appear in the smoo split (with only `crates/smoo-host-core/src/lib.rs` changes)
- The commit message stays the same in both splits

### Running Tests and Builds

```bash
# Test the full workspace
cargo check --workspace
cargo test --workspace

# Test desktop and web builds
dx build -p fastboop-desktop
dx build -p fastboop-web
```

---

## Pulling Updates from Canonical Repos

### Update smoo from upstream

```bash
git subtree pull --prefix=smoo https://github.com/samcday/smoo.git main
```

### Update gibblox from upstream

```bash
git subtree pull --prefix=gibblox https://github.com/samcday/gibblox.git main
```

**Note:** When gibblox canonical has erofs-rs subtree updates, they'll be included automatically in the gibblox subtree pull.

### Handling Merge Conflicts

If conflicts occur during `git subtree pull`:

1. Git will pause and show conflict markers in affected files
2. Resolve conflicts manually:
   ```bash
   # Edit conflicted files, then:
   git add <resolved-files>
   git commit  # Git will suggest a merge commit message
   ```
3. Or use a merge tool:
   ```bash
   git mergetool
   git commit
   ```

**The key insight:** Treat subtree merge conflicts the same as any normal git merge conflict. The subtree merge is just a regular git merge with the remote branch.

---

## Upstreaming Changes to Canonical Repos

When a fastboop development sprint has stabilized and you want to push changes back to canonical repos:

### Quick Reference Commands

```bash
# Split and push smoo changes
git subtree split --prefix=smoo -b smoo-upstream-sync
git push git@github.com:samcday/smoo.git smoo-upstream-sync:main
git branch -D smoo-upstream-sync

# Split and push gibblox changes
git subtree split --prefix=gibblox -b gibblox-upstream-sync
git push git@github.com:samcday/gibblox.git gibblox-upstream-sync:main
git branch -D gibblox-upstream-sync
```

### Detailed Workflow

#### 1. Split smoo Changes

```bash
# Create a branch containing only smoo commits
git subtree split --prefix=smoo -b smoo-upstream-sync

# Inspect the split (optional)
git log smoo-upstream-sync --oneline

# Push to canonical repo (direct to main)
git push git@github.com:samcday/smoo.git smoo-upstream-sync:main

# Or create a feature branch for PR
git push git@github.com:samcday/smoo.git smoo-upstream-sync:feature/fastboop-sprint-feb-2026

# Clean up the temporary branch
git branch -D smoo-upstream-sync
```

#### 2. Split gibblox Changes

```bash
# Create a branch containing only gibblox commits (including any erofs-rs changes at gibblox/erofs-rs/)
git subtree split --prefix=gibblox -b gibblox-upstream-sync

# Push to canonical repo
git push git@github.com:samcday/gibblox.git gibblox-upstream-sync:main

# Clean up
git branch -D gibblox-upstream-sync
```

#### 3. Handle erofs-rs Changes (if needed)

If you made changes to `gibblox/erofs-rs/` in fastboop:

1. Those changes are now in gibblox canonical after step 2
2. Switch to gibblox canonical repo (outside fastboop)
3. Split erofs-rs changes from gibblox:

```bash
cd /path/to/gibblox  # Your local clone of gibblox canonical

git pull origin main  # Get the changes you just pushed from fastboop

# Split erofs-rs changes
git subtree split --prefix=erofs-rs -b erofs-rs-upstream-sync

# Push to erofs-rs canonical
git push git@github.com:samcday/erofs-rs.git erofs-rs-upstream-sync:main

# Clean up
git branch -D erofs-rs-upstream-sync
```

### Handling Upstream Conflicts

If canonical repos have diverged (someone else pushed changes), you'll get a push rejection:

```bash
# Example: trying to push to smoo, but it has new commits
git push git@github.com:samcday/smoo.git smoo-upstream-sync:main
# ! [rejected]        smoo-upstream-sync -> main (non-fast-forward)
```

**Resolution:**

```bash
# Fetch the canonical repo state
git fetch git@github.com:samcday/smoo.git main

# Create a local tracking branch for canonical main
git branch smoo-canonical-main FETCH_HEAD

# Rebase your split branch onto canonical
git checkout smoo-upstream-sync
git rebase smoo-canonical-main

# Resolve conflicts if any (same as normal git rebase)
# Edit conflicted files, then:
git add <resolved-files>
git rebase --continue

# Now push (should fast-forward)
git push git@github.com:samcday/smoo.git smoo-upstream-sync:main

# Clean up
git checkout main  # or whatever branch you were on
git branch -D smoo-upstream-sync smoo-canonical-main
```

**Alternative: Create a PR instead**

If conflicts are complex or you want review:

```bash
# Push to a feature branch instead of main
git push git@github.com:samcday/smoo.git smoo-upstream-sync:feature/fastboop-upstream-feb-2026

# Then create a PR on GitHub and resolve conflicts there
```

---

## Advanced Scenarios

### Inspecting Subtree History

```bash
# See all commits that touched gibblox/ in fastboop
git log --oneline -- gibblox/

# See what the split would look like without creating a branch
git subtree split --prefix=gibblox --dry-run

# Show commits that will be in the split
git subtree split --prefix=gibblox --dry-run | xargs git log --oneline
```

### Checking if Subtrees are Up-to-Date

```bash
# Fetch canonical repos
git fetch https://github.com/samcday/gibblox.git main:gibblox-canonical-main
git fetch https://github.com/samcday/smoo.git main:smoo-canonical-main

# Check if subtree has canonical's latest commit
git log gibblox-canonical-main --oneline -1
# Compare with:
git log --oneline -1 -- gibblox/

# Clean up tracking branches
git branch -D gibblox-canonical-main smoo-canonical-main
```

### Rejecting a Subtree (Starting Over)

If you want to discard all local changes to a subtree and sync with canonical:

```bash
# Remove the subtree
git rm -r gibblox
git commit -m "Remove gibblox subtree"

# Re-add from canonical
git subtree add --prefix=gibblox https://github.com/samcday/gibblox.git main
```

**Warning:** This discards all local changes to that subtree!

---

## Common Pitfalls and Solutions

### Pitfall: Forgetting the `--prefix` argument

```bash
# Wrong
git subtree split -b gibblox-sync

# Correct
git subtree split --prefix=gibblox -b gibblox-sync
```

### Pitfall: Using the wrong prefix for nested subtrees

```bash
# Wrong: trying to split erofs-rs directly from fastboop
git subtree split --prefix=gibblox/erofs-rs -b erofs-rs-sync
# This won't work as expected because erofs-rs is part of gibblox's subtree content,
# not a direct subtree of fastboop

# Correct: split gibblox first, then split erofs-rs from gibblox canonical
```

### Pitfall: Accidentally pushing to wrong remote

```bash
# Always double-check the remote URL before pushing!
git push git@github.com:samcday/gibblox.git smoo-upstream-sync:main  # WRONG! smoo branch to gibblox repo

# Correct
git push git@github.com:samcday/smoo.git smoo-upstream-sync:main
```

### Pitfall: Losing track of which branches are split branches

```bash
# Use consistent naming
git subtree split --prefix=smoo -b smoo-upstream-sync    # Good
git subtree split --prefix=gibblox -b gibblox-upstream-sync  # Good

git subtree split --prefix=smoo -b tmp  # Bad - unclear what this is
```

---

## Git Subtree Quick Reference

| Command | Purpose |
|---------|---------|
| `git subtree add --prefix=DIR URL BRANCH` | Add a new subtree |
| `git subtree pull --prefix=DIR URL BRANCH` | Update subtree from canonical |
| `git subtree split --prefix=DIR -b BRANCH` | Extract subtree commits to branch |
| `git subtree push --prefix=DIR URL BRANCH` | Split and push in one command |

**Note:** We use `split` + manual `push` instead of `git subtree push` for better control and visibility.

---

## For AI Agents: Execution Checklist

When asked to upstream changes from fastboop:

1. **Check current state:**
   ```bash
   git status  # Ensure working tree is clean
   git log --oneline -10  # Review recent commits
   ```

2. **Split smoo:**
   ```bash
   git subtree split --prefix=smoo -b smoo-upstream-sync
   git log smoo-upstream-sync --oneline -10  # Verify split
   ```

3. **Push smoo (handle conflicts if needed):**
   ```bash
   git push git@github.com:samcday/smoo.git smoo-upstream-sync:main
   # If rejected: fetch, rebase, resolve conflicts, retry
   ```

4. **Split gibblox:**
   ```bash
   git subtree split --prefix=gibblox -b gibblox-upstream-sync
   git log gibblox-upstream-sync --oneline -10
   ```

5. **Push gibblox:**
   ```bash
   git push git@github.com:samcday/gibblox.git gibblox-upstream-sync:main
   ```

6. **Clean up:**
   ```bash
   git branch -D smoo-upstream-sync gibblox-upstream-sync
   ```

7. **If erofs-rs was modified:**
   - Notify user that erofs-rs changes need to be split from gibblox canonical
   - Optionally: if you have access to gibblox canonical repo, perform the split there

**Conflict Resolution Strategy:**
- Fetch canonical state: `git fetch REMOTE BRANCH`
- Rebase split branch: `git rebase FETCH_HEAD`
- For complex conflicts: create a feature branch and PR instead of pushing to main

---

## Migration History

**2026-02-08:** Migrated from git submodules to git subtrees
- **Phase 1:** gibblox migrated to use erofs-rs as subtree (commit: `268fe2b`)
- **Phase 2:** fastboop migrated to use gibblox and smoo as subtrees

**Submodule Commits (for reference):**
- gibblox: `53073b5` (pre-erofs-rs-subtree) → `268fe2b` (post-erofs-rs-subtree)
- smoo: `2943407`
- erofs-rs: `c3f265c`

---

## Additional Resources

- [Git Subtree Official Docs](https://github.com/git/git/blob/master/contrib/subtree/git-subtree.txt)
- [Atlassian Subtree Guide](https://www.atlassian.com/git/tutorials/git-subtree)

---

## Questions?

If you encounter a scenario not covered here, document it! This file is a living document meant to capture fastboop's subtree workflow patterns.
