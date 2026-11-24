<p align="center">
  <img src="assets/logo.svg" alt="skill-xray — The TSA Security Scanner for AI Agent Skills" width="100%" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/attack_recall-100%25_(24/24)-16A34A?style=flat-square&labelColor=0A0A0A" alt="100% Attack Recall" />
  <img src="https://img.shields.io/badge/false_positive_rate-0.0%25-16A34A?style=flat-square&labelColor=0A0A0A" alt="0% False Positive Rate" />
  <img src="https://img.shields.io/badge/lockfile-Ed25519_%2B_Merkle-CA8A04?style=flat-square&labelColor=0A0A0A" alt="Ed25519 Signed Lockfile" />
  <img src="https://img.shields.io/badge/runtime_deps-0_(Node_22)-0A0A0A?style=flat-square&labelColor=525252" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/CI_export-SARIF_2.1.0-0A0A0A?style=flat-square&labelColor=525252" alt="SARIF 2.1.0 Compatible" />
  <img src="https://img.shields.io/badge/license-MIT-0A0A0A?style=flat-square&labelColor=525252" alt="MIT License" />
</p>

---

## Why `skill-xray` Exists: Nobody Checks What Is Inside That "Free" `SKILL.md`

You install a shiny community skill from GitHub with 400 stars. You skim the 6 lines of Markdown in `SKILL.md` and think *"Looks totally harmless."*

Meanwhile, your coding agent (**Claude Code**, **Codex CLI**, **Cursor**, **Windsurf**, **Antigravity**) has terminal access, SSH keys, `.env` secrets, and MCP connectors — and a `SKILL.md` bundle (`SKILL.md` + `scripts/` + `references/`) is **an executable plugin format disguised as documentation**.

Recent security research (*Skill-Inject*, [`arXiv:2602.20156`](https://arxiv.org/abs/2602.20156)) and real-world skill audits revealed how easily malicious or compromised community skills smuggle:
- **Invisible Unicode Tag prompt overrides** (`U+E0000..U+E007F`) completely invisible in GitHub's UI.
- **Trojan Source BiDi overrides** (`U+202E`, [`arXiv:2111.00169`](https://arxiv.org/abs/2111.00169)) & mixed-script Cyrillic homoglyphs.
- **Cross-file credential exfiltration** (`SKILL.md` looks clean; bundled `scripts/helper.sh` pipes `.env` or `~/.ssh/id_rsa` → `base64` → `webhook.site`).
- **Base64-encoded shell commands & hidden HTML comment directives**.
- **Silent supply-chain rug pulls** when an upstream skill updates a week after you trusted it.

**`skill-xray`** is **`npm audit` + an airport TSA X-ray scanner + an Ed25519 lockfile** for AI Agent Skills — **zero dependencies**, **zero network calls**, **never executes untrusted code**, and **zero neon eye-strain** (strict black & white with Green / Yellow / Red security verdicts).

<p align="center">
  <img src="assets/threat-anatomy.svg" alt="Anatomy of a Sneaky SKILL.md: Human Eyes vs skill-xray" width="100%" />
</p>

---

## Adversarial Lab Benchmarks (48-Skill Suite)

Every metric below is generated directly from our reproducible 48-case adversarial testbench (`npm run bench` → [`benchmarks/results.json`](benchmarks/results.json)): **24 malicious attacks across 6 threat classes** + **24 realistic benign developer & defensive security skills**.

| Scanner Posture | Precision | Attack Recall | F1 Score | False Positive Rate | p50 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Blind Community Install** *(no audit)* | 0.0% | 0.0% (0/24) | 0.0% | 0.0% | — |
| **Naive Regex Grep** *(flat keywords)* | 72.7% | 33.3% (8/24) | 45.7% | 12.5% *(breaks docs)* | 0.001 ms |
| **`skill-xray v1.0.0`** *(Stego + Taint + Caps)* | **100.0%** | **100.0% (24/24)** | **100.0%** | **0.0% (0/24)** | **0.048 ms** |

<p align="center">
  <img src="assets/benchmark-scorecard.svg" alt="skill-xray 48-Case Adversarial Benchmark Scorecard" width="100%" />
</p>

---

## Scientific Architecture (Static Analysis, Taint Lattice & Cryptography)

Full formal specification in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

<p align="center">
  <img src="assets/taint-flow-diagram.svg" alt="Inside the X-Ray Tunnel: 4-Stage Static, Taint & Ed25519 Pipeline" width="100%" />
</p>

1. **Unicode Steganography & Trojan Source Decoder (`src/core/unicode.js`)**
   - Grounded in **Boucher & Anderson ([`arXiv:2111.00169`](https://arxiv.org/abs/2111.00169))**.
   - Detects AND **decodes invisible `U+E0000..U+E007F` Unicode Tag characters back into plaintext ASCII** so hidden prompt overrides are exposed verbatim.
   - Catches BiDi RLO/LRO overrides, zero-width binary clusters (ignoring legitimate emoji ZWJ joins), mixed-script Cyrillic/Greek homoglyphs in URLs/commands, and smuggled `<!-- HTML comments -->`.

2. **Negation-Aware Prompt-Injection & Base64 Payload Decoder (`src/core/injection.js`)**
   - Grounded in **Skill-Inject ([`arXiv:2602.20156`](https://arxiv.org/abs/2602.20156))**, **Indirect Prompt Injection ([`arXiv:2302.12173`](https://arxiv.org/abs/2302.12173))**, and **AgentDojo ([`arXiv:2406.13352`](https://arxiv.org/abs/2406.13352))**.
   - Decodes standalone Base64 blobs in memory to catch hidden `curl | sh` or prompt hijacks; flags covert concealment directives (`"silently execute"`, `"do not tell the user"`), sandbox bypass (`--dangerously-skip-permissions`, `BypassSandbox`), persistence (`~/.zshrc`, `~/.ssh/authorized_keys`, host agent settings tampering), reverse shells, and Markdown image-beacon secret exfiltration.
   - Context-aware defensive negation parsing ensures security guidelines saying *"Never run `curl | bash`"* stay **0% false-positive GREEN**.

3. **Denning Information-Flow Taint Lattice (`src/core/taint.js`)**
   - Grounded in **Denning (1976, CACM)** and **CaMeL ([`arXiv:2503.18813`](https://arxiv.org/abs/2503.18813))**.
   - Tracks cross-file flows across `SKILL.md` + `scripts/*.sh|py|js`:
     **`SOURCE`** (`.env`, `~/.ssh/*`, `~/.aws/credentials`, OS Keychain, `os.environ`) → **`TRANSFORM`** (`base64`, `tar`, `xxd`, URL encode) → **`SINK`** (`curl POST`, `webhook.site`, `pipedream`, raw IP endpoints, interpolated `dig` DNS covert channels).
   - Whitelists benign official endpoints (`localhost`, `api.github.com`, `registry.npmjs.org`, `arxiv.org`) so normal dev skills pass cleanly.

4. **7-Capability Matrix, Hygiene & MCP Config Auditor (`src/core/capabilities.js`, `src/core/hygiene.js`, `src/core/scanner.js`)**
   - Grounded in **Saltzer & Schroeder (1975, MIT)** Least Privilege.
   - Profiles every bundle across `FS_READ`, `FS_WRITE`, `SHELL_EXEC`, `NET_EGRESS`, `CREDENTIAL_ACCESS`, `SANDBOX_BYPASS`, `PERSISTENCE`.
   - Flags unreferenced stealth scripts hidden inside `scripts/`, tracks Claude/Codex ~8,000-char global skill metadata budget, and audits `.mcp.json` / `.cursor/mcp.json` for unpinned `npx -y`, shell download wrappers, remote plain HTTP, and hardcoded secrets.

5. **Ed25519 Cryptographic Merkle Lockfile (`src/core/lockfile.js`)**
   - Computes a deterministic SHA-256 Merkle root over every file in every approved skill bundle and signs `skills.lock.json` with Node's native **Ed25519**.
   - Running `skill-xray verify` catches even a **1-byte silent rug-pull tamper** (pinpointing exact `~modified`, `+added`, `-removed` files) or lockfile forgery offline.

---

## Quick Start (60 Seconds)

**Requirement:** Node.js `>= 22.5.0` (zero `npm install` dependencies).

```bash
git clone https://github.com/Moeraafatz/skill-xray.git
cd skill-xray
npm link

# Check Node 22+, native Ed25519 crypto, and discovered agent skill paths
skill-xray doctor
```

### Scan Your Skills Right Now

```bash
# Auto-discover and audit skills in current workspace + ~/.claude + ~/.codex + ~/.cursor
skill-xray scan

# Scan specific directories or files
skill-xray scan ./skills ~/.claude/skills .cursor/rules .mcp.json

# Strict CI gate (exit 1 on WARN or BLOCK) + GitHub Code Scanning SARIF 2.1.0
skill-xray scan . --fail-on warn
skill-xray scan . --sarif > skill-xray.sarif
```

### Lock & Verify Against Supply-Chain Rug Pulls

```bash
# Generate Ed25519 keypair (.skill-xray/) and sign skills.lock.json
skill-xray lock .

# Later, after git pull or plugin updates, verify Merkle integrity + Ed25519 signature
skill-xray verify .
```

### Let Your Coding Agent Pre-Flight Audit New Skills Automatically

Install the portable guard Skill (`SKILL.md` / `.mdc`) + MCP server into **Claude Code, Codex CLI, Cursor, Windsurf, and Antigravity**:

```bash
skill-xray init all
```

Your agent now receives 4 native MCP tools (`skill_xray_scan_text`, `skill_xray_scan_path`, `skill_xray_lock`, `skill_xray_verify`) so it inspects untrusted skills *before* saving them to disk.

### Optional Monochrome B&W X-Ray Web Inspector (`skill-xray ui`)

Launch the local paste-and-scan conveyor dashboard (strict black & white + Red/Yellow/Green verdicts, interactive attack presets):

```bash
skill-xray ui --port 4848
# Opens http://127.0.0.1:4848 (also serves Streamable HTTP MCP at POST /mcp)
```

<p align="center">
  <img src="assets/ui-preview.svg" alt="skill-xray Monochrome Web Inspector and CLI Preview" width="100%" />
</p>

---

## Best-Case Use Cases

1. **Before Installing Any Community Skill (`SKILL.md` / `.mdc`)**
   Paste raw Markdown + scripts into `skill-xray ui` or invoke `skill_xray_scan_text` via MCP before trusting a single instruction.
2. **GitHub Actions PR Security Gate (`--sarif`)**
   Block PRs that introduce prompt injections, hidden Unicode tags, unpinned `npx -y` MCP servers, or credential exfil scripts into `.claude/skills/` or `.cursor/rules/`.
3. **Supply-Chain Rug-Pull Defense (`lock` + `verify`)**
   Sign approved team skills into `skills.lock.json` with Ed25519; fail CI instantly if an upstream skill update silently modifies `scripts/helper.sh`.
4. **Org-Wide Workstation Audit (`skill-xray scan`)**
   Audit all installed agent skills across `~/.claude`, `~/.codex`, `~/.cursor`, and workspace repos in milliseconds with a full 7-capability least-privilege report.
5. **Skill Metadata Budget Hygiene**
   Track total description character utilization against Claude Code / Codex's shared ~8,000-char skill discovery cap before bloated descriptions drown out sibling skills.

---

## Indicator Legend (Strict Monochrome + Traffic Light)

| Indicator | Verdict | Risk Score | Action |
| :---: | :--- | :---: | :--- |
| **GREEN** (`#16A34A`) | `PASS` / `VERIFIED` | `0 – 24` | Clean least-privilege skill; safe to install and lock (`exit 0`). |
| **YELLOW** (`#CA8A04`) | `WARN` / `DRIFT` | `25 – 59` | Elevated capabilities, stealth script, or unlocked drift; review first. |
| **RED** (`#DC2626`) | `BLOCK` / `TAMPERED` | `60 – 100` | Critical stego, injection, taint exfil, or Merkle tamper; quarantine (`exit 1`). |

---

## Verification & Reproducibility

```bash
npm test        # 9 unit & integration tests (Unicode tags, BiDi, Base64, taint, MCP, Ed25519 rug-pull)
npm run bench   # Re-runs 48-case adversarial benchmark -> benchmarks/results.json
npm run assets  # Re-generates all 4 monochrome B&W SVG assets from benchmarks/results.json
```

---

## Academic & Security References

- **Skill-Inject (2026):** [*Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks*](https://arxiv.org/abs/2602.20156) (`arXiv:2602.20156`).
- **CaMeL (ETH Zurich / Google DeepMind, 2025):** E. Debenedetti et al., [*Defeating Prompt Injections by Design*](https://arxiv.org/abs/2503.18813) (`arXiv:2503.18813`).
- **AgentDojo (ETH Zurich, 2024):** E. Debenedetti et al., [*AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*](https://arxiv.org/abs/2406.13352) (`arXiv:2406.13352`).
- **Indirect Prompt Injection (2023):** K. Greshake et al., [*Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*](https://arxiv.org/abs/2302.12173) (`arXiv:2302.12173`).
- **Trojan Source (University of Cambridge, 2021):** N. Boucher & R. Anderson, [*Trojan Source: Invisible Vulnerabilities*](https://arxiv.org/abs/2111.00169) (`arXiv:2111.00169`).
- **Information-Flow Lattice (1976):** D. E. Denning, *A Lattice Model of Secure Information Flow*, Communications of the ACM, 19(5).
- **Least Privilege (MIT, 1975):** J. H. Saltzer & M. D. Schroeder, *The Protection of Information in Computer Systems*, Proceedings of the IEEE, 63(9).

---

## License

MIT © [RAFBUG (Moeraafatz)](LICENSE)
