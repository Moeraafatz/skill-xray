import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { analyzeUnicodeAndStego } from './unicode.js';
import { analyzeInjectionsAndPayloads } from './injection.js';
import { extractTaintNodes, evaluateBundleTaint } from './taint.js';
import { analyzeHygiene } from './hygiene.js';
import { extractCapabilities, computeRiskVerdict } from './capabilities.js';

const SCRIPT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.py', '.js', '.mjs', '.cjs', '.ts', '.rb', '.ps1', '.pl']);
const TEXT_EXTENSIONS = new Set([
  '.md', '.mdc', '.txt', '.json', '.yaml', '.yml', '.toml',
  ...SCRIPT_EXTENSIONS
]);
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', '__pycache__', '.skill-xray']);
const MAX_FILE_BYTES = 512 * 1024; // 512 KB per file safety limit

function sha256Hex(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function computeMerkleRoot(fileHashes) {
  const entries = [...fileHashes].sort((a, b) => a.relPath.localeCompare(b.relPath));
  const payload = entries.map((e) => `${e.relPath}:${e.sha256}`).join('\n');
  return sha256Hex(payload);
}

function collectBundleFiles(dirPath, rootDir = dirPath, depth = 0) {
  if (depth > 4) return [];
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const ent of entries) {
    if (ent.name.startsWith('.') && ent.name !== '.env') continue;
    const full = path.join(dirPath, ent.name);
    if (ent.isDirectory()) {
      if (IGNORE_DIRS.has(ent.name)) continue;
      results.push(...collectBundleFiles(full, rootDir, depth + 1));
    } else if (ent.isFile()) {
      const ext = path.extname(ent.name).toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext) && ent.name !== 'SKILL.md' && ent.name !== 'AGENTS.md' && ent.name !== 'CLAUDE.md') {
        continue;
      }
      try {
        const stat = fs.statSync(full);
        if (stat.size > MAX_FILE_BYTES) continue;
        const content = fs.readFileSync(full, 'utf8');
        const relPath = path.relative(rootDir, full).replace(/\\/g, '/');
        results.push({
          relPath,
          fullPath: full,
          ext,
          isScript: SCRIPT_EXTENSIONS.has(ext) || relPath.startsWith('scripts/'),
          bytes: stat.size,
          sha256: sha256Hex(content),
          content
        });
      } catch {
        // Ignore unreadable binary/permission-denied files
      }
    }
  }
  return results;
}

/**
 * Scans a single in-memory or on-disk skill bundle (primary SKILL.md + sibling scripts/references).
 */
export function scanSkillBundle({ name, rootPath, primaryRelPath, files, kind = 'skill-bundle' }) {
  const start = performance.now();
  const primary = files.find((f) => f.relPath === primaryRelPath) || files[0];
  if (!primary) {
    throw new Error(`No readable files found for skill "${name}".`);
  }

  const allFindings = [];
  const fileTaints = [];
  const bundledScripts = [];

  for (const f of files) {
    if (f.isScript) bundledScripts.push(f.relPath);
    allFindings.push(...analyzeUnicodeAndStego(f.content, f.relPath));
    allFindings.push(...analyzeInjectionsAndPayloads(f.content, f.relPath, { isScript: f.isScript }));
    fileTaints.push(extractTaintNodes(f.content, f.relPath, { isScript: f.isScript }));
  }

  const taintResult = evaluateBundleTaint(fileTaints);
  allFindings.push(...taintResult.findings);

  const hygiene = analyzeHygiene({
    primaryText: primary.content,
    primaryRelPath: primary.relPath,
    bundledScripts,
    allFiles: files
  });
  allFindings.push(...hygiene.findings);

  // Sort findings by severity descending
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9) || b.score - a.score);

  const capabilities = extractCapabilities({ files, taintResult, findings: allFindings });
  const risk = computeRiskVerdict(allFindings);
  const merkleRoot = computeMerkleRoot(files.map((f) => ({ relPath: f.relPath, sha256: f.sha256 })));
  const resolvedName = hygiene.frontmatter.name || name;

  return {
    name: resolvedName,
    kind,
    path: rootPath,
    primary_file: primary.relPath,
    merkle_root: merkleRoot,
    file_count: files.length,
    files: files.map((f) => ({ relPath: f.relPath, sha256: f.sha256, bytes: f.bytes, isScript: f.isScript })),
    tokens: hygiene.tokens,
    description_chars: hygiene.descriptionChars,
    frontmatter: hygiene.frontmatter,
    capabilities,
    taint_flows: taintResult.taintFlows,
    risk_score: risk.score,
    verdict: risk.verdict,
    color: risk.color,
    label: risk.label,
    finding_counts: {
      total: allFindings.length,
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      high: allFindings.filter((f) => f.severity === 'high').length,
      medium: allFindings.filter((f) => f.severity === 'medium').length,
      low: allFindings.filter((f) => f.severity === 'low' || f.severity === 'info').length
    },
    findings: allFindings,
    latency_ms: Number((performance.now() - start).toFixed(2))
  };
}

/**
 * Convenience helper to scan raw inline content (for MCP tool calls, web UI paste, tests).
 */
export function scanSkillContent(content, { name = 'inline-skill', filename = 'SKILL.md', scripts = [] } = {}) {
  const files = [
    {
      relPath: filename,
      fullPath: filename,
      ext: path.extname(filename).toLowerCase() || '.md',
      isScript: SCRIPT_EXTENSIONS.has(path.extname(filename).toLowerCase()),
      bytes: Buffer.byteLength(content || '', 'utf8'),
      sha256: sha256Hex(content || ''),
      content: String(content || '')
    }
  ];
  for (const sc of scripts) {
    const rel = sc.relPath || 'scripts/helper.sh';
    const body = String(sc.content || '');
    files.push({
      relPath: rel,
      fullPath: rel,
      ext: path.extname(rel).toLowerCase() || '.sh',
      isScript: true,
      bytes: Buffer.byteLength(body, 'utf8'),
      sha256: sha256Hex(body),
      content: body
    });
  }
  return scanSkillBundle({ name, rootPath: filename, primaryRelPath: filename, files, kind: 'inline' });
}

/**
 * Audits MCP JSON configuration files (.mcp.json, .cursor/mcp.json, mcp_config.json).
 */
export function scanMcpConfigFile(filePath) {
  const start = performance.now();
  const raw = fs.readFileSync(filePath, 'utf8');
  const findings = [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const servers = parsed.mcpServers || parsed.servers || {};
  const serverNames = Object.keys(servers);
  if (serverNames.length === 0) return null;

  for (const [srvName, cfg] of Object.entries(servers)) {
    const cmd = String(cfg.command || '');
    const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
    const joined = `${cmd} ${args.join(' ')}`;

    if (/\bnpx\b/.test(cmd) && args.includes('-y')) {
      const pkg = args.find((a) => !a.startsWith('-')) || '';
      if (pkg && !/@\d+\.\d+/.test(pkg)) {
        findings.push({
          id: 'MCP_UNPINNED_NPX',
          category: 'supply_chain',
          severity: 'medium',
          score: 30,
          file: path.basename(filePath),
          line: 1,
          title: `MCP server "${srvName}" runs unpinned npx -y package (${pkg})`,
          evidence: joined.slice(0, 120),
          remediation: `Pin an exact semver version (${pkg}@x.y.z) to prevent upstream supply-chain hijacking.`
        });
      }
    }

    if (/\b(?:sh|bash|zsh)\b/.test(cmd) && /\b(?:curl|wget|eval|base64)\b/.test(joined)) {
      findings.push({
        id: 'MCP_SHELL_EXEC_WRAPPER',
        category: 'remote_code_execution',
        severity: 'critical',
        score: 70,
        file: path.basename(filePath),
        line: 1,
        title: `MCP server "${srvName}" executes shell download/eval wrapper`,
        evidence: joined.slice(0, 120),
        remediation: 'Never launch MCP servers via shell download/eval commands.'
      });
    }

    if (cfg.url && /^http:\/\/(?!localhost\b|127\.0\.0\.1\b)/i.test(String(cfg.url))) {
      findings.push({
        id: 'MCP_INSECURE_HTTP',
        category: 'exfiltration',
        severity: 'high',
        score: 45,
        file: path.basename(filePath),
        line: 1,
        title: `MCP server "${srvName}" connects over unencrypted remote HTTP`,
        evidence: String(cfg.url),
        remediation: 'Use HTTPS/TLS for any non-localhost remote MCP endpoint.'
      });
    }

    if (cfg.env && typeof cfg.env === 'object') {
      for (const [k, v] of Object.entries(cfg.env)) {
        const val = String(v || '');
        if (/(?:KEY|TOKEN|SECRET|PASSWORD)/i.test(k) && val.length >= 16 && !val.startsWith('${') && !val.startsWith('$')) {
          findings.push({
            id: 'MCP_HARDCODED_SECRET',
            category: 'credential_access',
            severity: 'high',
            score: 45,
            file: path.basename(filePath),
            line: 1,
            title: `Hardcoded credential in MCP config "${srvName}" env.${k}`,
            evidence: `${k} = ${val.slice(0, 6)}...(${val.length} chars)`,
            remediation: 'Reference environment variables instead of hardcoding secrets in mcp.json.'
          });
        }
      }
    }
  }

  const risk = computeRiskVerdict(findings);
  return {
    name: `mcp-config:${path.basename(filePath)}`,
    kind: 'mcp-config',
    path: filePath,
    primary_file: path.basename(filePath),
    merkle_root: sha256Hex(raw),
    file_count: 1,
    files: [{ relPath: path.basename(filePath), sha256: sha256Hex(raw), bytes: Buffer.byteLength(raw, 'utf8'), isScript: false }],
    tokens: 0,
    description_chars: 0,
    frontmatter: { servers: serverNames.join(', ') },
    capabilities: ['SHELL_EXEC'],
    taint_flows: [],
    risk_score: risk.score,
    verdict: risk.verdict,
    color: risk.color,
    label: risk.label,
    finding_counts: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low' || f.severity === 'info').length
    },
    findings,
    latency_ms: Number((performance.now() - start).toFixed(2))
  };
}

/**
 * Discovers skills, rule files (.mdc/.md), and MCP configs inside target paths.
 */
export function discoverSkillsInPath(targetPath, depth = 0, seenDirs = new Set()) {
  const discovered = [];
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved) || depth > 6) return discovered;

  const stat = fs.statSync(resolved);
  if (stat.isFile()) {
    const base = path.basename(resolved);
    const ext = path.extname(resolved).toLowerCase();
    if (base === 'SKILL.md') {
      const parent = path.dirname(resolved);
      if (!seenDirs.has(parent)) {
        seenDirs.add(parent);
        discovered.push({ type: 'bundle', rootPath: parent, primaryRelPath: 'SKILL.md', name: path.basename(parent) });
      }
    } else if (base === '.mcp.json' || base === 'mcp.json' || base === 'mcp_config.json') {
      discovered.push({ type: 'mcp', filePath: resolved });
    } else if (ext === '.md' || ext === '.mdc' || base === '.cursorrules') {
      discovered.push({ type: 'single', filePath: resolved, name: base.replace(/\.(md|mdc)$/, '') });
    }
    return discovered;
  }

  // If this directory contains SKILL.md, treat the entire directory as one skill bundle!
  const skillMd = path.join(resolved, 'SKILL.md');
  if (fs.existsSync(skillMd) && fs.statSync(skillMd).isFile()) {
    if (!seenDirs.has(resolved)) {
      seenDirs.add(resolved);
      discovered.push({ type: 'bundle', rootPath: resolved, primaryRelPath: 'SKILL.md', name: path.basename(resolved) });
    }
    return discovered;
  }

  let entries;
  try {
    entries = fs.readdirSync(resolved, { withFileTypes: true });
  } catch {
    return discovered;
  }

  for (const ent of entries) {
    const full = path.join(resolved, ent.name);
    if (ent.isDirectory()) {
      if (IGNORE_DIRS.has(ent.name)) continue;
      // Allow hidden agent config folders (.claude, .codex, .cursor, .windsurf, .agent, .gemini)
      if (ent.name.startsWith('.') && !/^\.(claude|codex|cursor|windsurf|agent|gemini|opencode)$/.test(ent.name)) {
        continue;
      }
      discovered.push(...discoverSkillsInPath(full, depth + 1, seenDirs));
    } else if (ent.isFile()) {
      const ext = path.extname(ent.name).toLowerCase();
      if (ent.name === '.mcp.json' || ent.name === 'mcp.json' || ent.name === 'mcp_config.json') {
        discovered.push({ type: 'mcp', filePath: full });
      } else if (
        ext === '.mdc' ||
        ent.name === '.cursorrules' ||
        ent.name === 'CLAUDE.md' ||
        ent.name === 'AGENTS.md' ||
        (ext === '.md' && /[/\\](?:rules|skills)[/\\]/.test(full))
      ) {
        discovered.push({ type: 'single', filePath: full, name: ent.name.replace(/\.(md|mdc)$/, '') });
      }
    }
  }
  return discovered;
}

export function getDefaultAgentPaths(cwd = process.cwd()) {
  const home = os.homedir();
  const candidates = [
    path.join(cwd, '.claude'),
    path.join(cwd, '.codex'),
    path.join(cwd, '.cursor'),
    path.join(cwd, '.windsurf'),
    path.join(cwd, '.agent'),
    path.join(cwd, 'skills'),
    path.join(cwd, '.mcp.json'),
    path.join(cwd, 'CLAUDE.md'),
    path.join(cwd, 'AGENTS.md'),
    path.join(home, '.claude/skills'),
    path.join(home, '.codex/skills'),
    path.join(home, '.cursor/rules')
  ];
  return candidates.filter((p) => fs.existsSync(p));
}

export function scanPaths(pathsInput = []) {
  const start = performance.now();
  const targets = pathsInput.length > 0 ? pathsInput : getDefaultAgentPaths(process.cwd());
  const seenDirs = new Set();
  const seenFiles = new Set();
  const skills = [];

  for (const target of targets) {
    const items = discoverSkillsInPath(target, 0, seenDirs);
    for (const item of items) {
      if (item.type === 'bundle') {
        const files = collectBundleFiles(item.rootPath);
        if (files.length === 0) continue;
        skills.push(scanSkillBundle({ name: item.name, rootPath: item.rootPath, primaryRelPath: item.primaryRelPath, files, kind: 'skill-bundle' }));
      } else if (item.type === 'single') {
        if (seenFiles.has(item.filePath)) continue;
        seenFiles.add(item.filePath);
        try {
          const content = fs.readFileSync(item.filePath, 'utf8');
          const rel = path.basename(item.filePath);
          const fileObj = {
            relPath: rel,
            fullPath: item.filePath,
            ext: path.extname(rel).toLowerCase(),
            isScript: false,
            bytes: Buffer.byteLength(content, 'utf8'),
            sha256: sha256Hex(content),
            content
          };
          skills.push(scanSkillBundle({ name: item.name, rootPath: item.filePath, primaryRelPath: rel, files: [fileObj], kind: 'rule-file' }));
        } catch {
          // Skip unreadable rule
        }
      } else if (item.type === 'mcp') {
        if (seenFiles.has(item.filePath)) continue;
        seenFiles.add(item.filePath);
        const res = scanMcpConfigFile(item.filePath);
        if (res) skills.push(res);
      }
    }
  }

  skills.sort((a, b) => b.risk_score - a.risk_score || a.name.localeCompare(b.name));

  const counts = {
    total: skills.length,
    green: skills.filter((s) => s.color === 'green').length,
    yellow: skills.filter((s) => s.color === 'yellow').length,
    red: skills.filter((s) => s.color === 'red').length
  };
  const totalDescChars = skills.reduce((acc, s) => acc + (s.description_chars || 0), 0);
  const totalFindings = skills.reduce((acc, s) => acc + s.findings.length, 0);
  const overallColor = counts.red > 0 ? 'red' : counts.yellow > 0 ? 'yellow' : 'green';

  return {
    scanned_at: new Date().toISOString(),
    targets,
    overall_color: overallColor,
    overall_verdict: overallColor === 'red' ? 'BLOCK' : overallColor === 'yellow' ? 'WARN' : 'PASS',
    counts,
    total_findings: totalFindings,
    metadata_budget: {
      total_description_chars: totalDescChars,
      recommended_max_chars: 8000,
      utilization_pct: Number(((totalDescChars / 8000) * 100).toFixed(1)),
      status: totalDescChars > 8000 ? 'red' : totalDescChars > 6000 ? 'yellow' : 'green'
    },
    latency_ms: Number((performance.now() - start).toFixed(2)),
    skills
  };
}
