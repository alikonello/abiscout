# abiscout — scout a contract’s attack surface from the ABI (offline)

**abiscout** takes ABI JSON files and produces a concise map of your contract’s
**attack surface** — with function selectors, payable externals, fallback/receive
behavior, and high-signal buckets like **owner/role mutators**, **upgrade hooks**,
and **token permission** methods (approve/permit/setApprovalForAll). No RPC needed.

## Why this is useful

- ABI is the *interface*. You can learn a lot about risk just from names, mutability,
  and obvious patterns (grantRole, upgradeTo, initialize, approve).
- Pre-review PRs and releases: drop ABIs in, get a **diff-friendly CSV/JSON** and a tiny **SVG badge**.
- Great for CI: fail builds if new upgrade/admin endpoints appear.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
