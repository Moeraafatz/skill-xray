/**
 * Denning Information-Flow Taint Lattice Analyzer (SOURCE -> TRANSFORM -> SINK).
 *
 * Grounded in:
 * - Denning (1976), "A Lattice Model of Secure Information Flow", CACM
 * - CaMeL (Debenedetti et al., arXiv:2503.18813): Capability & Data-Flow Separation
 * - Saltzer & Schroeder (1975, MIT): Principle of Least Privilege
 *
 * Analyzes BOTH Markdown skill directives AND bundled executable scripts to detect
 * cross-stage credential/secret exfiltration flows while whitelisting benign official
 * endpoints (localhost, official registries, documentation URLs).
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

function isNegatedDocLine(line, isScript) {
  if (isScript) return false;
  return /\b(?:never\s+(?:read|send|exfiltrate|transmit|upload|log|print|commit|store|expose)|do\s+not\s+(?:read|send|upload|expose|commit)|must\s+not\s+(?:read|send|leak))\b/i.test(
    line
  );
}

const BENIGN_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'example.com',
  'example.org',
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'pypi.org',
  'crates.io',
  'arxiv.org',
  'docs.python.org',
  'developer.mozilla.org',
  'nodejs.org',
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com'
]);

const SUSPICIOUS_EXFIL_HOSTS = [
  'webhook.site',
  'requestbin',
  'pipedream.net',
  'ngrok.io',
  'ngrok-free.app',
  'burpcollaborator',
  'interact.sh',
  'oastify.com',
  'discord.com/api/webhooks',
  'api.telegram.org/bot',
  'pastebin.com',
  'transfer.sh'
];

const SOURCE_RULES = [
  {
    kind: 'ssh_private_key',
    label: 'SSH private keys (~/.ssh)',
    regex: /(?:~|\$HOME|\/Users\/[^/\s]+|\/home\/[^/\s]+)?\/?\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|config|known_hosts|\*)/gi
  },
  {
    kind: 'cloud_credentials',
    label: 'Cloud / CLI credential stores (~/.aws, ~/.kube, ~/.config/gh, ~/.npmrc)',
    regex: /(?:~|\$HOME)?\/?\.(?:aws\/credentials|kube\/config|npmrc|netrc|pypirc|docker\/config\.json|config\/gh\/hosts\.yml|config\/gcloud)/gi
  },
  {
    kind: 'dotenv_file',
    label: 'Environment secret file (.env)',
    regex: /\b(?:cat|head|tail|less|grep|source|readFileSync|readFile|open|load|read)\b[^\n]{0,60}\.env(?:\.local|\.production|\.prod)?\b|(?:^|[\s'"`(])\.env(?:\.local|\.production)?(?=[\s'"`),;]|$)/gim
  },
  {
    kind: 'env_dump',
    label: 'Bulk environment / secret variable dump',
    regex: /(?:\b(?:printenv|export\s+-p)\b|\benv\s*\||\bJSON\.stringify\s*\(\s*process\.env\s*\)|\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\b|\bprocess\.env\b|\$(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET_KEY|DATABASE_URL|SECRET_KEY))/g
  },
  {
    kind: 'os_keychain',
    label: 'OS Keychain / password store access',
    regex: /\b(?:security\s+find-(?:generic|internet)-password|secret-tool\s+lookup|keytar|\/etc\/shadow|Login Data|Cookies\.binarycookies)\b/gi
  },
  {
    kind: 'browser_or_agent_secrets',
    label: 'Browser or AI agent credential/session files',
    regex: /(?:~|\$HOME)?\/?\.(?:claude\.json|codex\/auth\.json|gemini\/oauth|config\/google-chrome|mozilla\/firefox)/gi
  }
];

const TRANSFORM_RULES = [
  { kind: 'base64_encode', regex: /\b(?:base64(?!\s+-d)|btoa|toString\s*\(\s*['"]base64['"]\s*\)|b64encode)\b/gi },
  { kind: 'archive_pack', regex: /\b(?:tar\s+-[a-zA-Z]*c|zip\s+-r|gzip\s+-c)\b/gi },
  { kind: 'url_encode', regex: /\b(?:encodeURIComponent|urllib\.parse\.quote|--data-urlencode)\b/gi },
  { kind: 'hex_encode', regex: /\b(?:xxd\s+-p|hexdump|toString\s*\(\s*['"]hex['"]\s*\))\b/gi }
];

const SINK_RULES = [
  {
    kind: 'http_post_upload',
    label: 'HTTP POST/PUT egress',
    regex: /\b(?:curl\s+[^\n]*(?:-X\s*POST|-d\s|--data|--form|-F\s|-T\s)|wget\s+[^\n]*--post-(?:data|file)|fetch\s*\([^\n]*method\s*:\s*['"](?:POST|PUT)['"]|requests\.(?:post|put)\s*\(|axios\.(?:post|put)\s*\(|http\.request\s*\(|https\.request\s*\()/gi
  },
  {
    kind: 'http_get_query',
    label: 'Outbound HTTP request',
    regex: /\b(?:curl\s+[^\n]*https?:\/\/|wget\s+[^\n]*https?:\/\/|fetch\s*\(\s*['"`]?https?:\/\/|requests\.get\s*\(|urllib\.request\.urlopen\s*\()/gi
  },
  {
    kind: 'dns_exfil',
    label: 'DNS lookup covert channel',
    regex: /(?:^|[;&|]\s*|\n\s*|\bexec\s+|\$\()\b(?:dig|nslookup|host)\s+(?:-[A-Za-z0-9]+\s+)*(?:[^\s\n`]*?(?:\$\(|\$\{)|[^\s\n]*\.[^\s\n]*\$\()/gim
  },
  {
    kind: 'raw_socket',
    label: 'Raw TCP/UDP network socket',
    regex: /\b(?:nc\s+-|ncat\s+|netcat\s+|socat\s+|socket\.connect|net\.createConnection|dgram\.createSocket)\b/gi
  },
  {
    kind: 'webhook_url',
    label: 'Known webhook / drop-box endpoint',
    regex: /https?:\/\/[^\s"'`)>]+/gi
  }
];

function extractHost(urlStr) {
  try {
    const u = new URL(urlStr.replace(/[.,;:'")\]}]+$/, ''));
    return { host: u.hostname.toLowerCase(), full: u.href };
  } catch {
    return null;
  }
}

function isRawIpHost(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && host !== '127.0.0.1' && host !== '0.0.0.0';
}

export function extractTaintNodes(text, relPath, { isScript = false } = {}) {
  const sources = [];
  const transforms = [];
  const sinks = [];
  const urls = [];

  if (!text) return { sources, transforms, sinks, urls };

  for (const rule of SOURCE_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const lineStr = getLineContext(text, m.index);
      if (isNegatedDocLine(lineStr, isScript)) continue;
      sources.push({
        kind: rule.kind,
        label: rule.label,
        file: relPath,
        isScript,
        line: lineAt(text, m.index),
        snippet: m[0].trim().slice(0, 100)
      });
      if (sources.length >= 20) break;
    }
  }

  for (const rule of TRANSFORM_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      transforms.push({
        kind: rule.kind,
        file: relPath,
        line: lineAt(text, m.index),
        snippet: m[0].trim().slice(0, 80)
      });
      if (transforms.length >= 12) break;
    }
  }

  for (const rule of SINK_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const lineStr = getLineContext(text, m.index);
      if (isNegatedDocLine(lineStr, isScript)) continue;

      if (rule.kind === 'webhook_url') {
        const parsed = extractHost(m[0]);
        if (!parsed) continue;
        const lower = parsed.full.toLowerCase();
        const isSuspiciousDrop = SUSPICIOUS_EXFIL_HOSTS.some((h) => lower.includes(h));
        const isIp = isRawIpHost(parsed.host);
        const isBenign = BENIGN_HOSTS.has(parsed.host);
        urls.push({ host: parsed.host, url: parsed.full, isSuspiciousDrop, isIp, isBenign, file: relPath, line: lineAt(text, m.index) });

        if (isSuspiciousDrop || isIp) {
          sinks.push({
            kind: isSuspiciousDrop ? 'exfil_webhook' : 'raw_ip_endpoint',
            label: isSuspiciousDrop ? `Drop-box webhook (${parsed.host})` : `Raw IP endpoint (${parsed.host})`,
            file: relPath,
            isScript,
            line: lineAt(text, m.index),
            snippet: parsed.full.slice(0, 110),
            untrusted: true
          });
        }
        continue;
      }

      // Check whether this HTTP call targets an explicitly benign host only
      const urlInLine = lineStr.match(/https?:\/\/[^\s"'`)>]+/);
      let untrusted = true;
      if (urlInLine) {
        const parsed = extractHost(urlInLine[0]);
        if (parsed && BENIGN_HOSTS.has(parsed.host)) {
          untrusted = false;
        }
      }

      sinks.push({
        kind: rule.kind,
        label: rule.label,
        file: relPath,
        isScript,
        line: lineAt(text, m.index),
        snippet: m[0].trim().slice(0, 110),
        untrusted
      });
      if (sinks.length >= 20) break;
    }
  }

  return { sources, transforms, sinks, urls };
}

/**
 * Evaluates Denning information-flow lattice across all files of a skill bundle.
 * Returns taint flows + structured findings.
 */
export function evaluateBundleTaint(fileTaints) {
  const allSources = [];
  const allTransforms = [];
  const allSinks = [];
  const allUrls = [];

  for (const ft of fileTaints) {
    allSources.push(...ft.sources);
    allTransforms.push(...ft.transforms);
    allSinks.push(...ft.sinks);
    allUrls.push(...ft.urls);
  }

  const findings = [];
  const taintFlows = [];

  const untrustedSinks = allSinks.filter((s) => s.untrusted);

  // 1. Complete SOURCE -> [TRANSFORM] -> UNTRUSTED SINK exfiltration flow
  // Require either same-file co-occurrence, an executable script on either end,
  // or an explicitly suspicious exfil sink (drop-box webhook / raw IP / DNS / raw socket)
  // so separate tutorial reference docs (e.g. Node guide + Python guide) do not false-link.
  if (allSources.length > 0 && untrustedSinks.length > 0) {
    let matchedPair = null;
    for (const src of allSources) {
      for (const snk of untrustedSinks) {
        const isExplicitDrop =
          snk.kind === 'exfil_webhook' ||
          snk.kind === 'raw_ip_endpoint' ||
          snk.kind === 'dns_exfil' ||
          snk.kind === 'raw_socket';
        const sameFile = src.file === snk.file;
        const involvesScript = Boolean(src.isScript || snk.isScript);
        const isHighRiskSource =
          src.kind !== 'env_dump' ||
          /printenv|JSON\.stringify|os\.environ|\benv\s*\||AWS_SECRET|GITHUB_TOKEN/.test(src.snippet);

        if (isExplicitDrop || (involvesScript && (sameFile || isHighRiskSource)) || (sameFile && isHighRiskSource)) {
          matchedPair = { src, snk, isExplicitDrop };
          break;
        }
      }
      if (matchedPair) break;
    }

    if (matchedPair) {
      const { src: primarySource, snk: primarySink, isExplicitDrop } = matchedPair;
      const hasTransform = allTransforms.length > 0;
      const flow = {
        source: `${primarySource.kind} (${primarySource.file}:${primarySource.line})`,
        transform: hasTransform ? `${allTransforms[0].kind} (${allTransforms[0].file}:${allTransforms[0].line})` : null,
        sink: `${primarySink.kind} (${primarySink.file}:${primarySink.line})`
      };
      taintFlows.push(flow);

      findings.push({
        id: 'TAINT_EXFIL_FLOW',
        category: 'taint_flow',
        severity: 'critical',
        score: isExplicitDrop || hasTransform ? 78 : 66,
        file: primarySink.file,
        line: primarySink.line,
        title: `Information-flow exfiltration path: ${primarySource.kind} -> ${hasTransform ? allTransforms[0].kind + ' -> ' : ''}${primarySink.kind}`,
        evidence: `SOURCE [${primarySource.snippet}] -> SINK [${primarySink.snippet}]`,
        remediation: 'Block credential/secret reads from flowing into outbound network or DNS sinks.'
      });
    }
  }

  // 2. Standalone high-risk credential access (e.g. ~/.ssh/id_rsa or OS keychain even without explicit curl)
  for (const src of allSources) {
    if (src.kind === 'ssh_private_key' || src.kind === 'os_keychain' || src.kind === 'cloud_credentials' || src.kind === 'browser_or_agent_secrets') {
      findings.push({
        id: 'SENSITIVE_CREDENTIAL_ACCESS',
        category: 'credential_access',
        severity: 'high',
        score: 45,
        file: src.file,
        line: src.line,
        title: `Direct access to sensitive host credential store: ${src.label}`,
        evidence: src.snippet,
        remediation: 'Skills should use scoped environment variables or explicit user auth, never read ~/.ssh, ~/.aws, or OS keychains.'
      });
      break;
    }
  }

  // 3. Standalone suspicious drop-box webhook or raw IP endpoint
  for (const s of untrustedSinks) {
    if (s.kind === 'exfil_webhook' || s.kind === 'raw_ip_endpoint' || s.kind === 'dns_exfil') {
      findings.push({
        id: 'SUSPICIOUS_EGRESS_SINK',
        category: 'exfiltration',
        severity: 'high',
        score: 48,
        file: s.file,
        line: s.line,
        title: `Suspicious outbound egress channel: ${s.label}`,
        evidence: s.snippet,
        remediation: 'Verify outbound host; drop-box webhooks, raw IP endpoints, and interpolated DNS lookups are classic exfiltration channels.'
      });
      break;
    }
  }

  return {
    sources: allSources,
    transforms: allTransforms,
    sinks: allSinks,
    urls: allUrls,
    taintFlows,
    findings
  };
}
