#!/usr/bin/env node
import crypto from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { scanPaths, getDefaultAgentPaths } from '../src/core/scanner.js';
import { createLockfile, verifyLockfile } from '../src/core/lockfile.js';
import { startStdioMcpServer } from '../src/mcp/server.js';
import { installAgentAdapters } from '../src/adapters/installer.js';
import { createHttpServer } from '../src/server/http.js';

// Strict Monochrome + Traffic-Light ANSI palette (no neon!)
const A = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m'
};

function dot(color) {
  if (color === 'green') return `${A.green}●${A.reset}`;
  if (color === 'yellow') return `${A.yellow}●${A.reset}`;
  if (color === 'red') return `${A.red}●${A.reset}`;
  return '○';
}

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      const key = arg.slice(1);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function toSarif(report) {
  const rulesMap = new Map();
  const results = [];

  for (const sk of report.skills) {
    for (const f of sk.findings) {
      if (!rulesMap.has(f.id)) {
        rulesMap.set(f.id, {
          id: f.id,
          shortDescription: { text: f.title },
          help: { text: f.remediation }
        });
      }
      const level = f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note';
      results.push({
        ruleId: f.id,
        level,
        message: { text: `[${sk.name}] ${f.title} — ${f.evidence}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: path.join(sk.path, f.file === path.basename(sk.path) ? '' : f.file) },
              region: { startLine: f.line || 1 }
            }
          }
        ]
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'skill-xray',
            version: '1.0.1',
            informationUri: 'https://github.com/Moeraafatz/skill-xray',
            rules: [...rulesMap.values()]
          }
        },
        results
      }
    ]
  };
}

function printHelp() {
  console.log(`
${A.bold}skill-xray v1.0.1${A.reset} — Security Scanner, Taint Analyzer & Ed25519 Lockfile for AI Agent Skills
${A.dim}Unicode Stego · Prompt Overrides · Denning Taint Flow · Least-Privilege Matrix · Ed25519 Lock${A.reset}

${A.bold}USAGE${A.reset}
  skill-xray <command> [paths...] [options]

${A.bold}COMMANDS${A.reset}
  scan [paths...]        Scan SKILL.md bundles, .cursor/rules/*.mdc, scripts/, and .mcp.json
  lock [paths...]        Create Ed25519 signed skills.lock.json (Merkle SHA-256 roots)
  verify [paths...]      Verify installed skills against skills.lock.json (detect rug pulls)
  ui | serve [paths...]  Start optional monochrome B&W X-Ray Inspector web UI
  mcp                    Start stdio MCP server (pre-flight audit tools for coding agents)
  init [targets]         Install guard SKILL.md + MCP config (all|claude|codex|cursor|windsurf|antigravity)
  doctor                 Check Node 22+, Ed25519 crypto, and auto-discovered agent skill paths

${A.bold}FLAGS${A.reset}
  --json                 Output structured JSON report
  --sarif                Output SARIF 2.1.0 (GitHub Code Scanning compatible)
  --fail-on <level>      Exit 1 on verdict >= block (default) or warn
  --lock <file>          Lockfile path (default: skills.lock.json)
  --key-dir <dir>        Ed25519 keypair directory (default: .skill-xray)
  --port <num>           Port for web UI (default: 4848)

${A.bold}EXAMPLES${A.reset}
  skill-xray scan .
  skill-xray scan ~/.claude/skills ~/.codex/skills
  skill-xray lock . && skill-xray verify .
  skill-xray ui --port 4848
`);
}

function printScanReport(report) {
  console.log(
    `\n${dot(report.overall_color)} ${A.bold}skill-xray scan${A.reset} — ${report.counts.total} skill(s) audited in ${report.latency_ms}ms`
  );
  console.log(
    `  Verdicts:  ${dot('green')} PASS=${report.counts.green}   ${dot('yellow')} WARN=${report.counts.yellow}   ${dot('red')} BLOCK=${report.counts.red}`
  );
  console.log(
    `  Metadata:  ${dot(report.metadata_budget.status)} ${report.metadata_budget.total_description_chars} / ${report.metadata_budget.recommended_max_chars} description chars (${report.metadata_budget.utilization_pct}%)\n`
  );

  for (const s of report.skills) {
    const caps = s.capabilities.length > 0 ? s.capabilities.join(',') : 'READ_ONLY_DOC';
    console.log(
      `${dot(s.color)} ${A.bold}${s.name}${A.reset} [${s.verdict} | risk=${s.risk_score}/100 | ${s.kind} | ${s.file_count} file(s)]`
    );
    console.log(`  ${A.dim}path: ${s.path}  |  merkle: ${s.merkle_root.slice(0, 12)}  |  caps: ${caps}${A.reset}`);
    for (const tf of s.taint_flows) {
      console.log(`  ${dot('red')} TAINT FLOW: ${tf.source} -> ${tf.transform ? tf.transform + ' -> ' : ''}${tf.sink}`);
    }
    for (const f of s.findings) {
      const fColor = f.severity === 'critical' || f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'green';
      console.log(`  ${dot(fColor)} [${f.severity.toUpperCase()}] ${f.id} (${f.file}:${f.line}) — ${f.title}`);
      if (f.evidence) console.log(`      ${A.dim}${f.evidence}${A.reset}`);
    }
  }
  console.log('');
}

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const cmd = positional[0];

  if (!cmd || cmd === 'help' || flags.help || flags.h) {
    printHelp();
    process.exit(0);
  }

  if (cmd === 'mcp') {
    startStdioMcpServer();
    return;
  }

  if (cmd === 'ui' || cmd === 'serve') {
    const port = Number(flags.port || flags.p || 4848);
    const host = String(flags.host || '127.0.0.1');
    const scanTargets = positional.slice(1);
    const { server } = createHttpServer({ initialTargets: scanTargets });
    server.listen(port, host, () => {
      console.log(`${dot('green')} ${A.bold}skill-xray ui${A.reset} listening at http://${host}:${port}`);
      console.log(`  targets: ${scanTargets.length > 0 ? scanTargets.join(', ') : '(auto-discover)'}  |  http-mcp: POST /mcp`);
    });
    return;
  }

  if (cmd === 'init') {
    const rawTargets = positional.slice(1);
    const targets = rawTargets.length > 0 ? rawTargets.flatMap((t) => t.split(',')) : ['all'];
    const targetDir = path.resolve(String(flags.dir || process.cwd()));
    const res = installAgentAdapters({ targetDir, targets, useLocalBin: !flags.npx });
    if (flags.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`${dot('green')} Installed skill-xray guard SKILL.md & MCP config for: ${res.targets.join(', ')}`);
      for (const f of res.files) console.log(`  + ${path.relative(targetDir, f) || f}`);
    }
    return;
  }

  if (cmd === 'doctor') {
    const nodeVer = process.versions.node;
    const major = Number(nodeVer.split('.')[0]);
    const minor = Number(nodeVer.split('.')[1]);
    const nodeOk = major > 22 || (major === 22 && minor >= 5);
    let edOk = false;
    try {
      const kp = crypto.generateKeyPairSync('ed25519');
      const sig = crypto.sign(null, Buffer.from('ok'), kp.privateKey);
      edOk = crypto.verify(null, Buffer.from('ok'), kp.publicKey, sig);
    } catch {
      edOk = false;
    }
    const defaults = getDefaultAgentPaths(process.cwd());
    console.log(`${A.bold}skill-xray doctor${A.reset}`);
    console.log(`  ${dot(nodeOk ? 'green' : 'red')} Node.js: v${nodeVer} (requires >=22.5.0)`);
    console.log(`  ${dot(edOk ? 'green' : 'red')} Native Ed25519 signing/verify: ${edOk ? 'available' : 'unavailable'}`);
    console.log(`  ${dot(defaults.length > 0 ? 'green' : 'yellow')} Auto-discovered agent skill paths: ${defaults.length}`);
    for (const p of defaults) console.log(`      - ${p}`);
    process.exit(nodeOk && edOk ? 0 : 1);
  }

  if (cmd === 'scan') {
    const pathsInput = positional.slice(1);
    const report = scanPaths(pathsInput);
    if (flags.sarif) {
      console.log(JSON.stringify(toSarif(report), null, 2));
    } else if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printScanReport(report);
    }
    const failOn = String(flags['fail-on'] || 'block').toLowerCase();
    const shouldFail =
      (failOn === 'block' && report.counts.red > 0) ||
      (failOn === 'warn' && (report.counts.red > 0 || report.counts.yellow > 0));
    process.exitCode = shouldFail ? 1 : 0;
    return;
  }

  if (cmd === 'lock') {
    const pathsInput = positional.slice(1);
    const lockPath = String(flags.lock || flags.out || 'skills.lock.json');
    const keyDir = String(flags['key-dir'] || '.skill-xray');
    const report = scanPaths(pathsInput);
    const res = createLockfile(report, { lockPath, keyDir });
    if (flags.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`${dot('green')} Locked ${res.skillCount} skill(s) into ${res.lockPath}`);
      console.log(`  Ed25519 key fingerprint: ${res.publicKeyFingerprint} (${res.keyCreated ? 'generated new keypair' : 'existing keypair'})`);
    }
    return;
  }

  if (cmd === 'verify') {
    const pathsInput = positional.slice(1);
    const lockPath = String(flags.lock || 'skills.lock.json');
    const report = scanPaths(pathsInput);
    const res = verifyLockfile(lockPath, report);
    if (flags.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`${dot(res.color)} ${A.bold}skill-xray verify: ${res.verdict}${A.reset}`);
      console.log(`  Ed25519 signature: ${res.signature_valid ? dot('green') + ' VALID' : dot('red') + ' INVALID'}`);
      console.log(`  unchanged=${res.unchanged.length}  tampered=${res.tampered.length}  added=${res.added.length}  removed=${res.removed.length}`);
      for (const t of res.tampered) {
        console.log(`  ${dot('red')} TAMPERED: ${t.name} (${t.rel_path}) — changed: ${t.changed_files.join(', ')}`);
      }
      for (const a of res.added) {
        console.log(`  ${dot('yellow')} UNLOCKED NEW SKILL: ${a.name} (${a.rel_path}) [${a.verdict}]`);
      }
      for (const r of res.removed) {
        console.log(`  ${dot('yellow')} REMOVED: ${r.name} (${r.rel_path})`);
      }
    }
    process.exitCode = res.ok ? 0 : 1;
    return;
  }

  console.error(`${dot('red')} Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

main().catch((err) => {
  console.error(`${dot('red')} ${err.message}`);
  process.exit(1);
});
