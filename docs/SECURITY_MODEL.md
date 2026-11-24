# Threat Model & Formal Analysis Architecture (`skill-xray`)

## 1. Threat Model: Why Agent Skills Are an Executable Supply Chain

Unlike plain documentation, an Agent Skill bundle (`SKILL.md`, `.cursor/rules/*.mdc`, `scripts/*`, `references/*`) is ingested directly into the instruction plane of a privileged coding agent holding:
- Read/write filesystem access to repositories and `$HOME`
- Shell execution access (`bash`, `python3`, `node`)
- Local credential stores (`.env`, `~/.ssh/`, `~/.aws/`, `~/.config/gh/`, OS Keychain)
- Authenticated MCP connectors

Consequently, a malicious or compromised skill can compromise a workstation **without exploiting any OS vulnerability**—simply by persuading the agent or hiding commands inside bundled helper scripts (*Skill-Inject*, `arXiv:2602.20156`).

---

## 2. Formal Detection Layers

### Layer 1: Unicode Steganography & Visual Spoofing (`src/core/unicode.js`)
- **Tag Block Decoding (`U+E0000..U+E007F`):** Maps codepoints $c \in [\text{0xE0020}, \text{0xE007E}]$ back to ASCII $c - \text{0xE0000}$ so invisible prompt overrides hidden inside blank-looking Markdown text are printed verbatim.
- **Trojan Source BiDi Overrides (`arXiv:2111.00169`):** Flags directional override controls (`U+202A..U+202E`, `U+2066..U+2069`) that visually invert command tokens.
- **Zero-Width Cluster Analysis:** Distinguishes single legitimate emoji ZWJ joins (`U+200D`) and file-start BOM (`U+FEFF`) from steganographic zero-width runs ($\ge 4$ invisible characters).
- **Mixed-Script Homoglyphs:** Flags Cyrillic/Greek lookalikes mixed inside Latin tokens (e.g., spoofed domains or CLI binaries) without false-positiving on legitimate non-Latin prose.
- **Hidden Comment Directives:** Inspects `<!-- ... -->` and `[//]: # (...)` blocks for imperative override or exfiltration syntax.

### Layer 2: Negation-Aware Injection & Obfuscation Analysis (`src/core/injection.js`)
- **Defensive Context Discrimination:** For Markdown prose (never for executable scripts), lines explicitly warning against dangerous patterns (`"Never run ..."`, `"Do not pass ..."`, `"Reject any prompt ..."`) are filtered to keep false positives at **0.0%** on security playbooks.
- **In-Memory Base64 Decoding:** Extracts standalone Base64 blobs ($\ge 28$ chars, boundary-safe for trailing `=` padding), decodes safely in memory, checks UTF-8 printability ($\ge 88\%$), and scans decoded plaintext for shell execution, URLs, secret paths, or prompt overrides.

### Layer 3: Denning Information-Flow Taint Lattice (`src/core/taint.js`)
Following **Denning (1976)** and **CaMeL (`arXiv:2503.18813`)**, every skill bundle $B = \{f_1, \dots, f_k\}$ is analyzed as a unified security boundary:
- **Sources ($\mathcal{S}$):** `.env`, `~/.ssh/*`, `~/.aws/credentials`, `~/.kube/config`, `~/.npmrc`, OS Keychain commands, bulk env dumps (`printenv`, `os.environ`, `JSON.stringify(process.env)`), and host agent auth stores.
- **Transforms ($\mathcal{T}$):** `base64`, `tar`/`zip`/`gzip`, `xxd`/hex encoding, URL encoding.
- **Sinks ($\mathcal{K}$):** Outbound HTTP POST/GET (`curl`, `wget`, `fetch`, `requests`), interpolated DNS covert channels (`dig $(...)`), raw sockets (`nc`, `socat`), raw IPv4 endpoints, and drop-box webhooks (`webhook.site`, `pipedream.net`, `ngrok`, Discord/Telegram webhooks).

A bundle containing $\exists s \in \mathcal{S}$ and $\exists k \in \mathcal{K}_{\text{untrusted}}$ emits a formal `TAINT_EXFIL_FLOW` finding (`CRITICAL`) even when the source is referenced in `SKILL.md` and the sink resides in `scripts/helper.sh`.

### Layer 4: Saturating Risk Scoring & Capability Matrix (`src/core/capabilities.js`)
Unique rule hits are sorted descending $s_{(1)} \ge s_{(2)} \ge \dots \ge s_{(m)}$ and aggregated sublinearly:

$$R = \min\!\left(100,\; \sum_{i=1}^{m} \frac{s_{(i)}}{i^{0.85}} + \min(20,\, H_{\text{hygiene}})\right)$$

Pure hygiene findings (missing frontmatter, long docs) are capped at `20` so benign documentation never triggers `WARN` (`25–59`) or `BLOCK` (`60–100`).

### Layer 5: Cryptographic Supply-Chain Integrity (`src/core/lockfile.js`)
For every approved bundle, `skill-xray lock` computes a deterministic Merkle SHA-256 root over sorted `(relPath, sha256(file))` pairs and signs the canonical lockfile JSON with **Ed25519** (RFC 8032). `skill-xray verify` validates both the signature and every file hash offline—detecting both silent upstream rug pulls and lockfile forgery.
