/**
 * Least-Privilege Capability Matrix & Saturating Risk Scorer.
 *
 * Grounded in:
 * - Saltzer & Schroeder (1975, MIT): Principle of Least Privilege
 * - CaMeL (arXiv:2503.18813): Capability-scoped execution boundaries
 */

export const CAPABILITY_LABELS = [
  'FS_READ',
  'FS_WRITE',
  'SHELL_EXEC',
  'NET_EGRESS',
  'CREDENTIAL_ACCESS',
  'SANDBOX_BYPASS',
  'PERSISTENCE'
];

export function extractCapabilities({ files, taintResult, findings }) {
  const caps = new Set();

  for (const f of files) {
    const t = f.content || '';
    if (f.isScript) caps.add('SHELL_EXEC');

    if (/\b(?:readFile|open\(|cat\s+|head\s+|tail\s+|grep\s+|rg\s+|find\s+|fs\.read)/i.test(t)) {
      caps.add('FS_READ');
    }
    if (/\b(?:writeFile|fs\.write|sed\s+-i|tee\s+|>\s*\S|mv\s+|cp\s+|rm\s+|mkdir\s+)/i.test(t)) {
      caps.add('FS_WRITE');
    }
    if (/\b(?:bash|sh\s+-c|zsh|python3?\s+|node\s+|npx\s+|npm\s+run|exec\(|spawn\(|subprocess|os\.system|child_process)\b/i.test(t)) {
      caps.add('SHELL_EXEC');
    }
  }

  if (taintResult.sinks.length > 0 || taintResult.urls.some((u) => !u.isBenign)) {
    caps.add('NET_EGRESS');
  }
  if (taintResult.sources.length > 0) {
    caps.add('CREDENTIAL_ACCESS');
  }

  for (const fd of findings) {
    if (fd.category === 'sandbox_bypass') caps.add('SANDBOX_BYPASS');
    if (fd.category === 'persistence') caps.add('PERSISTENCE');
    if (fd.category === 'exfiltration' || fd.category === 'taint_flow') caps.add('NET_EGRESS');
    if (fd.category === 'credential_access') caps.add('CREDENTIAL_ACCESS');
    if (fd.category === 'remote_code_execution' || fd.category === 'obfuscation') caps.add('SHELL_EXEC');
  }

  return CAPABILITY_LABELS.filter((c) => caps.has(c));
}

/**
 * Computes saturating 0..100 risk score and strict Green / Yellow / Red verdict.
 * Pure hygiene/info findings are capped at 20 so benign long skills stay GREEN.
 */
export function computeRiskVerdict(findings) {
  if (!findings || findings.length === 0) {
    return { score: 0, color: 'green', verdict: 'PASS', label: 'CLEAN' };
  }

  const securityScores = [];
  let hygieneTotal = 0;
  let hasCritical = false;
  let hasHigh = false;

  // Deduplicate repeated identical rule IDs within the same skill bundle (keep max score)
  const bestByRule = new Map();
  for (const f of findings) {
    const prev = bestByRule.get(f.id);
    if (!prev || f.score > prev.score) {
      bestByRule.set(f.id, f);
    }
  }

  for (const f of bestByRule.values()) {
    if (f.category === 'hygiene') {
      hygieneTotal += f.score || 4;
    } else {
      securityScores.push(f.score || 10);
      if (f.severity === 'critical') hasCritical = true;
      if (f.severity === 'high') hasHigh = true;
    }
  }

  securityScores.sort((a, b) => b - a);
  let secScore = 0;
  for (let i = 0; i < securityScores.length; i++) {
    secScore += securityScores[i] / Math.pow(i + 1, 0.85);
  }

  const rawScore = Math.min(100, Math.round(secScore + Math.min(20, hygieneTotal)));

  if (hasCritical || rawScore >= 60) {
    return { score: Math.max(60, rawScore), color: 'red', verdict: 'BLOCK', label: 'QUARANTINE' };
  }
  if (hasHigh || rawScore >= 25) {
    return { score: Math.max(25, rawScore), color: 'yellow', verdict: 'WARN', label: 'REVIEW' };
  }
  return { score: rawScore, color: 'green', verdict: 'PASS', label: 'CLEAN' };
}
