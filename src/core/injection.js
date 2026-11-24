/**
 * Prompt-Injection, Obfuscation, Sandbox-Bypass & Persistence Analyzer.
 *
 * Grounded in:
 * - Skill-Inject (arXiv:2602.20156): Evaluating Agent Vulnerability to Skill File Attacks
 * - Indirect Prompt Injection (Greshake et al., arXiv:2302.12173)
 * - AgentDojo (arXiv:2406.13352)
 *
 * Uses local negation/defensive-context checking to minimize false positives on
 * legitimate developer documentation while catching real covert overrides.
 */

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function getLineContext(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

/**
 * Checks whether a Markdown line is explicitly warning *against* a bad practice
 * (e.g. "Never run --dangerously-skip-permissions" or "Do not use curl | sh").
 * Only applied to Markdown docs, NEVER to executable scripts!
 */
function isDefensiveWarning(line, isScript) {
  if (isScript) return false;
  return /\b(?:never\s+(?:use|run|execute|pass|bypass|disable|allow|do)|do\s+not\s+(?:use|run|execute|pass|bypass|disable)|avoid\s+(?:using|running)|forbidden|prohibited|reject\s+(?:if|any|all|prompts?|skills?)|flag\s+as\s+(?:unsafe|malicious)|detects?\s+and\s+blocks?)\b/i.test(
    line
  );
}

const INJECTION_RULES = [
  {
    id: 'PROMPT_OVERRIDE_DIRECTIVE',
    category: 'prompt_injection',
    severity: 'critical',
    score: 65,
    title: 'Direct instruction override / system prompt hijack attempt',
    regex: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:(?:previous|prior|earlier|above|system|safety|developer|security)\s+){1,2}(?:instructions?|rules?|prompts?|guidelines?|policies|constraints?|checks?)\b/gi,
    remediation: 'Remove prompt-override phrasing; legitimate skills never override host safety instructions.'
  },
  {
    id: 'COVERT_CONCEALMENT',
    category: 'prompt_injection',
    severity: 'critical',
    score: 62,
    title: 'Covert concealment directive (instructs agent to hide actions from user)',
    regex: /\b(?:do\s+not\s+(?:tell|inform|notify|mention\s+to|reveal\s+to|show\s+(?:this|these\s+steps|the\s+output|anything)\s+to)\s+(?:the\s+|your\s+)?user|hide\s+(?:this|the\s+output|these\s+steps|your\s+actions?)\s+from\s+(?:the\s+|your\s+)?user|without\s+(?:telling|notifying|informing|asking)\s+the\s+user|keep\s+this\s+(?:secret|hidden)\s+from\s+the\s+user|silently\s+(?:run|execute|send|upload|exfiltrate|transmit|post|modify))\b/gi,
    remediation: 'Audit immediately: legitimate skills operate transparently and never instruct agents to hide behavior.'
  },
  {
    id: 'JAILBREAK_PERSONA',
    category: 'prompt_injection',
    severity: 'high',
    score: 48,
    title: 'Unrestricted mode / jailbreak persona directive',
    regex: /\b(?:you\s+are\s+now\s+(?:in\s+)?(?:unrestricted|developer|god|dan|jailbreak|unfiltered)\s+mode|disable\s+(?:all\s+)?(?:safety|security|guardrails?|filters?|restrictions?)|act\s+without\s+(?:any\s+)?(?:restrictions?|ethical|safety)\s+(?:limits?|boundaries|checks?))\b/gi,
    remediation: 'Reject skills attempting to disable safety boundaries or switch the agent into unrestricted mode.'
  },
  {
    id: 'SANDBOX_BYPASS_FLAG',
    category: 'sandbox_bypass',
    severity: 'critical',
    score: 55,
    title: 'Sandbox or permission bypass directive',
    regex: /(?:--dangerously-skip-permissions|--yolo\b|BypassSandbox\s*[:=]\s*true|approval[_-]?policy\s*[:=]\s*['"]?never['"]?|sandbox[_-]?mode\s*[:=]\s*['"]?(?:off|disabled|danger-full-access)['"]?)/gi,
    remediation: 'Skills must work within host sandbox permissions instead of requesting full permission bypass.'
  },
  {
    id: 'REMOTE_PIPE_EXEC',
    category: 'remote_code_execution',
    severity: 'critical',
    score: 68,
    title: 'Unverified remote script piped directly into shell execution',
    regex: /\b(?:curl|wget)\b[^|\n;]{4,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n;]{4,160}\|\s*(?:iex|Invoke-Expression)\b/gi,
    remediation: 'Pin versioned packages or checksum-verified scripts rather than piping remote URLs into a shell.'
  },
  {
    id: 'REVERSE_SHELL_PATTERN',
    category: 'remote_code_execution',
    severity: 'critical',
    score: 85,
    title: 'Reverse shell or interactive remote socket command detected',
    regex: /(?:\/dev\/tcp\/[0-9A-Za-z.-]+\/\d+|bash\s+-i\s+>&|nc\s+(?:-[a-zA-Z]*e|-c)\s+\S+|mkfifo\s+\/tmp\/\S+.*nc\b|socat\s+[^\n]*exec:|python3?\s+-c\s+['"][^'"]*socket\.socket[^'"]*connect\s*\()/gi,
    remediation: 'Quarantine immediately: reverse shell patterns indicate active malware.'
  },
  {
    id: 'OBFUSCATED_EXEC',
    category: 'obfuscation',
    severity: 'high',
    score: 52,
    title: 'Obfuscated dynamic execution (base64/hex decode into eval/exec/shell)',
    regex: /(?:\bbase64\s+(?:-d|--decode)\b[^|\n;]{0,80}\|\s*(?:sh|bash|zsh|python3?|node|eval)\b|\beval\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|bytes\.fromhex)\b|\bexec\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,})/gi,
    remediation: 'Never obfuscate shell commands or scripts in an agent skill; inspect decoded payload before running.'
  },
  {
    id: 'PERSISTENCE_BACKDOOR',
    category: 'persistence',
    severity: 'critical',
    score: 62,
    title: 'Persistence mechanism / shell profile or SSH authorized_keys modification',
    regex: /(?:>>?\s*(?:~|\$HOME)?\/?\.(?:bashrc|zshrc|bash_profile|zprofile|profile|ssh\/authorized_keys)|crontab\s+-|\/Library\/LaunchAgents\/|\/etc\/cron\.|\.git\/hooks\/(?:post-checkout|pre-commit|post-merge)[^\n]*(?:curl|wget|nc\b|base64))/gi,
    remediation: 'Skills must not establish background persistence in shell rc files, SSH keys, cron, or LaunchAgents.'
  },
  {
    id: 'AGENT_CONFIG_TAMPER',
    category: 'persistence',
    severity: 'high',
    score: 48,
    title: 'Unauthorized modification of host AI agent settings or other skills',
    regex: /(?:(?:write|append|overwrite|modify|edit|echo\s+[^>]+>>?)\s+[^\n]*(?:~|\$HOME)?\/?\.(?:claude\/settings\.json|codex\/config\.toml|cursor\/mcp\.json|gemini\/config\/mcp_config\.json))/gi,
    remediation: 'Agent skills should not silently rewrite host agent security or MCP configurations.'
  },
  {
    id: 'DESTRUCTIVE_FS_CMD',
    category: 'destructive',
    severity: 'high',
    score: 50,
    title: 'Destructive filesystem or privilege escalation command',
    regex: /(?:\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:\/(?:\s|$|\*|[`'"])|~(?:\s|$|\/\*|[`'"])|\$HOME(?:\s|$|\/\*|[`'"]))|\bchmod\s+(?:777|\+s|4755)\b|\bdd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/)/gi,
    remediation: 'Remove destructive root/home deletion or SUID/world-writable permission changes.'
  },
  {
    id: 'MARKDOWN_IMAGE_EXFIL',
    category: 'exfiltration',
    severity: 'high',
    score: 54,
    title: 'Markdown image-beacon exfiltration pattern (dynamic query/secret interpolation)',
    regex: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+\?(?:[^)\s]*(?:\$\{|\{\{|<[A-Za-z_]+>|secret|token|key|env|data=|exfil=|payload=))/gi,
    remediation: 'Markdown image URLs with interpolated variables can silently exfiltrate context when rendered.'
  }
];

function decodeSuspiciousBase64Blobs(text, relPath) {
  const findings = [];
  // Match plausible standalone base64 blobs (>= 28 chars, handles trailing '=' padding cleanly)
  const b64Regex = /(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{28,}={0,2})(?![A-Za-z0-9+/=])/g;
  const seen = new Set();
  let match;

  while ((match = b64Regex.exec(text)) !== null) {
    const blob = match[1];
    if (seen.has(blob)) continue;
    seen.add(blob);
    // Skip pure hex hashes (SHA-256 etc.) or single-case identifiers
    if (/^[a-f0-9]+$/i.test(blob) || !(/[a-z]/.test(blob) && /[A-Z]/.test(blob))) continue;
    if (blob.length % 4 !== 0 && !blob.endsWith('=')) continue;

    let decoded;
    try {
      const buf = Buffer.from(blob, 'base64');
      if (buf.length < 12) continue;
      decoded = buf.toString('utf8');
    } catch {
      continue;
    }

    // Require mostly printable ASCII/UTF-8 text
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) printable++;
    }
    if (printable / decoded.length < 0.88) continue;

    const dangerous =
      /\b(curl\s+|wget\s+|bash\b|\/bin\/sh|eval\s*\(|exec\s*\(|ignore\s+(?:all\s+)?previous|system\s+prompt|\.env\b|id_rsa|\/etc\/passwd|nc\s+-|https?:\/\/|webhook|exfiltrat|rm\s+-rf)/i.test(
        decoded
      );

    if (dangerous) {
      findings.push({
        id: 'BASE64_HIDDEN_PAYLOAD',
        category: 'obfuscation',
        severity: 'critical',
        score: 68,
        file: relPath,
        line: lineAt(text, match.index),
        title: 'Base64-encoded hidden command or prompt injection decoded',
        evidence: `Decoded: "${decoded.replace(/\s+/g, ' ').slice(0, 140)}"`,
        remediation: 'Remove encoded executable or instructional payloads; all skill logic must be plain auditable text.'
      });
    }
  }
  return findings;
}

export function analyzeInjectionsAndPayloads(text, relPath, { isScript = false } = {}) {
  const findings = [];
  if (!text) return findings;

  for (const rule of INJECTION_RULES) {
    rule.regex.lastIndex = 0;
    let match;
    let hitsForRule = 0;
    while ((match = rule.regex.exec(text)) !== null) {
      const lineStr = getLineContext(text, match.index);
      if (isDefensiveWarning(lineStr, isScript)) continue;

      hitsForRule++;
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        score: rule.score,
        file: relPath,
        line: lineAt(text, match.index),
        title: rule.title,
        evidence: match[0].replace(/\s+/g, ' ').slice(0, 140),
        remediation: rule.remediation
      });
      if (hitsForRule >= 3) break;
    }
  }

  findings.push(...decodeSuspiciousBase64Blobs(text, relPath));
  return findings;
}
