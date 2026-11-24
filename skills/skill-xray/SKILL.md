---
name: skill-xray
description: Security pre-flight auditor for AI Agent Skills (SKILL.md, .cursor/rules/*.mdc, scripts/, MCP configs). Run before installing, trusting, or updating third-party skills to detect Unicode steganography, prompt overrides, taint exfiltration, and supply-chain tampering.
---

# skill-xray — Agent Skill Security Protocol

Run `skill-xray` before installing or activating any unfamiliar third-party `SKILL.md`, rule file, or MCP configuration.

## Pre-Flight Audit Workflow

1. **Inspect Before Saving (`skill_xray_scan_text`)**
   - When reviewing a skill fetched from GitHub, a registry, or a pull request, call `skill_xray_scan_text` with its Markdown and bundled scripts before writing files into `.claude/skills/`, `.codex/skills/`, `.cursor/rules/`, or `.agent/skills/`.

2. **Scan Workspace & Installed Skills (`skill_xray_scan_path`)**
   - Audit project or home skill folders to review each skill's 7-capability profile, Denning taint flows, Unicode integrity, and metadata budget footprint.

3. **Respect Traffic-Light Verdicts**
   - **GREEN (`PASS`, score 0–24):** Clean least-privilege skill. Safe to install and lock.
   - **YELLOW (`WARN`, score 25–59):** Elevated capabilities or medium warnings. Review every flagged line with the user before enabling.
   - **RED (`BLOCK`, score 60–100):** Critical findings (hidden Unicode tags, BiDi overrides, covert overrides, taint exfiltration, reverse shells, or tampering). Quarantine and refuse installation.

4. **Lock & Verify Supply Chain (`skill_xray_lock` / `skill_xray_verify`)**
   - After approving workspace skills, lock their SHA-256 Merkle roots with Ed25519 (`skills.lock.json`).
   - Run `skill_xray_verify` after git pulls or plugin updates to catch silent rug-pull modifications.

## CLI Usage

```bash
# Scan workspace skills and MCP configs
skill-xray scan .

# Lock approved skills with Ed25519 signature
skill-xray lock .

# Verify against lockfile in CI or after updates
skill-xray verify .

# Export SARIF 2.1.0 for GitHub Code Scanning
skill-xray scan . --sarif > skill-xray.sarif
```
