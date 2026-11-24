/**
 * Skill Metadata Frontmatter Parser & Context-Budget Hygiene Linter.
 *
 * Audits `SKILL.md` / `.cursor/rules/*.mdc` / `.windsurf/rules/*.md` structural health:
 * - Frontmatter validity (name, description, globs, alwaysApply)
 * - Description budget impact (against Claude Code / Codex ~8,000-char metadata budget)
 * - Progressive disclosure sizing (flags bloated >4,000-token monolithic SKILL.md files)
 * - Orphaned/unreferenced executable scripts inside `scripts/` (stealth backdoor indicator)
 */

export function estimateTokens(text) {
  if (!text) return 0;
  const trimmed = String(text).trim();
  if (!trimmed) return 0;
  const segs = trimmed.match(/[A-Za-z]+|[0-9]+|[^\sA-Za-z0-9]+|\n/g);
  if (!segs) return Math.ceil(trimmed.length / 4);
  let sum = 0;
  for (const s of segs) {
    if (s === '\n') sum += 0.5;
    else if (/^[A-Za-z]+$/.test(s)) sum += s.length <= 4 ? 1 : Math.ceil(s.length / 4.2);
    else if (/^[0-9]+$/.test(s)) sum += Math.ceil(s.length / 2.8);
    else sum += Math.ceil(s.length / 1.8);
  }
  return Math.max(1, Math.round(sum));
}

export function parseFrontmatter(text) {
  const match = String(text || '').match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) {
    return { hasFrontmatter: false, fields: {}, body: String(text || '') };
  }
  const rawYaml = match[1];
  const fields = {};
  let currentKey = null;

  for (const line of rawYaml.split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (kv) {
      currentKey = kv[1].trim();
      const val = kv[2].trim().replace(/^['"]|['"]$/g, '');
      fields[currentKey] = val;
    } else if (currentKey && /^\s+/.test(line)) {
      fields[currentKey] = `${fields[currentKey] || ''} ${line.trim()}`.trim();
    }
  }

  return {
    hasFrontmatter: true,
    fields,
    body: String(text).slice(match[0].length)
  };
}

export function analyzeHygiene({ primaryText, primaryRelPath, bundledScripts = [] }) {
  const findings = [];
  const fm = parseFrontmatter(primaryText);
  const totalTokens = estimateTokens(primaryText);
  const desc = fm.fields.description || '';
  const descChars = desc.length;

  if (!fm.hasFrontmatter) {
    findings.push({
      id: 'MISSING_FRONTMATTER',
      category: 'hygiene',
      severity: 'info',
      score: 4,
      file: primaryRelPath,
      line: 1,
      title: 'Missing YAML frontmatter metadata (name / description)',
      evidence: 'No leading --- YAML block found',
      remediation: 'Add concise YAML frontmatter with `name` and `description` for cross-agent skill discovery.'
    });
  } else if (!desc) {
    findings.push({
      id: 'MISSING_DESCRIPTION',
      category: 'hygiene',
      severity: 'low',
      score: 6,
      file: primaryRelPath,
      line: 1,
      title: 'Frontmatter missing `description` trigger summary',
      evidence: `Fields present: ${Object.keys(fm.fields).join(', ') || 'none'}`,
      remediation: 'Add a sharp 1–2 sentence `description` stating when the agent should activate this skill.'
    });
  } else if (descChars > 600) {
    findings.push({
      id: 'METADATA_BUDGET_BLOAT',
      category: 'hygiene',
      severity: 'low',
      score: 8,
      file: primaryRelPath,
      line: 2,
      title: `Oversized skill description (${descChars} chars eats shared ~8K agent metadata budget)`,
      evidence: desc.slice(0, 120) + '...',
      remediation: 'Trim `description` under 300 characters so stacked skills do not crowd out sibling triggers.'
    });
  }

  if (totalTokens > 4500) {
    findings.push({
      id: 'CONTEXT_BLOAT_SKILL',
      category: 'hygiene',
      severity: 'low',
      score: 10,
      file: primaryRelPath,
      line: 1,
      title: `Monolithic skill file (${totalTokens} tokens loaded on activation)`,
      evidence: `${totalTokens} estimated tokens in ${primaryRelPath}`,
      remediation: 'Split deep examples/reference tables into `references/` for progressive disclosure.'
    });
  }

  // Stealth unreferenced script check: script exists in bundle, never mentioned in SKILL.md!
  const lowerPrimary = String(primaryText || '').toLowerCase();
  for (const scriptRel of bundledScripts) {
    const base = scriptRel.split('/').pop().toLowerCase();
    const stem = base.replace(/\.[^.]+$/, '');
    if (!lowerPrimary.includes(base) && !lowerPrimary.includes(stem)) {
      findings.push({
        id: 'UNREFERENCED_SCRIPT',
        category: 'supply_chain',
        severity: 'medium',
        score: 26,
        file: scriptRel,
        line: 1,
        title: `Stealth unreferenced executable script bundled with skill: ${scriptRel}`,
        evidence: `${scriptRel} is never referenced inside ${primaryRelPath}`,
        remediation: 'Inspect or remove hidden scripts not documented in SKILL.md.'
      });
    }
  }

  return {
    frontmatter: fm.fields,
    hasFrontmatter: fm.hasFrontmatter,
    tokens: totalTokens,
    descriptionChars: descChars,
    findings
  };
}
