import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(__dirname, '../..');
const SKILL_SRC = path.join(PACKAGE_ROOT, 'skills/skill-xray/SKILL.md');

function writeSafe(targetPath, content) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, content, 'utf8');
  return targetPath;
}

function mergeMcpJson(targetPath, entry) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  let existing = {};
  if (fs.existsSync(targetPath)) {
    try {
      existing = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
    } catch {
      existing = {};
    }
  }
  existing.mcpServers = existing.mcpServers || {};
  existing.mcpServers['skill-xray'] = entry;
  fs.writeFileSync(targetPath, JSON.stringify(existing, null, 2) + '\n', 'utf8');
  return targetPath;
}

function toCursorRule(body) {
  const stripped = body.replace(/^---[\s\S]*?---\s*/, '');
  return `---
description: Security pre-flight skill auditor via skill-xray MCP before installing or running third-party agent skills.
alwaysApply: false
---

${stripped}`;
}

export function installAgentAdapters({
  targetDir = process.cwd(),
  targets = ['all'],
  useLocalBin = true
} = {}) {
  const skillBody = fs.readFileSync(SKILL_SRC, 'utf8');
  const binPath = path.join(PACKAGE_ROOT, 'bin/skill-xray.js');
  const entry = useLocalBin
    ? { command: 'node', args: [binPath, 'mcp'] }
    : { command: 'npx', args: ['-y', 'skill-xray@1.0.0', 'mcp'] };

  const selected = new Set(targets.includes('all') ? ['claude', 'codex', 'cursor', 'windsurf', 'antigravity'] : targets);
  const files = [];

  if (selected.has('claude')) {
    files.push(writeSafe(path.join(targetDir, '.claude/skills/skill-xray/SKILL.md'), skillBody));
    files.push(mergeMcpJson(path.join(targetDir, '.mcp.json'), entry));
  }
  if (selected.has('codex')) {
    files.push(writeSafe(path.join(targetDir, '.codex/skills/skill-xray/SKILL.md'), skillBody));
    const toml = `# Append to ~/.codex/config.toml or project .codex/config.toml
[mcp_servers.skill-xray]
command = "${entry.command}"
args = ${JSON.stringify(entry.args)}
`;
    files.push(writeSafe(path.join(targetDir, '.codex/skill-xray.config.toml'), toml));
  }
  if (selected.has('cursor')) {
    files.push(writeSafe(path.join(targetDir, '.cursor/rules/skill-xray.mdc'), toCursorRule(skillBody)));
    files.push(mergeMcpJson(path.join(targetDir, '.cursor/mcp.json'), entry));
  }
  if (selected.has('windsurf')) {
    files.push(writeSafe(path.join(targetDir, '.windsurf/rules/skill-xray.md'), skillBody));
  }
  if (selected.has('antigravity')) {
    files.push(writeSafe(path.join(targetDir, '.agent/skills/skill-xray/SKILL.md'), skillBody));
  }

  return { targets: [...selected], files, mcpEntry: entry };
}
