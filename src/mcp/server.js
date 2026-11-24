import { scanPaths, scanSkillContent } from '../core/scanner.js';
import { createLockfile, verifyLockfile } from '../core/lockfile.js';

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = {
  name: 'skill-xray',
  version: '1.0.0'
};

export const MCP_TOOLS = [
  {
    name: 'skill_xray_scan_path',
    description:
      'Audit local agent skill directories, SKILL.md bundles, .cursor/rules/*.mdc files, and .mcp.json configs for Unicode steganography, prompt overrides, Denning taint exfiltration, sandbox bypass, and metadata bloat.',
    inputSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional list of directories or files to scan (defaults to auto-discovered agent skill directories).'
        }
      }
    }
  },
  {
    name: 'skill_xray_scan_text',
    description:
      'Pre-flight audit raw untrusted SKILL.md markdown and optional bundled script contents BEFORE saving them to disk.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Skill name (default: "candidate-skill").' },
        content: { type: 'string', description: 'Raw SKILL.md or rule text to inspect.' },
        scripts: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              relPath: { type: 'string' },
              content: { type: 'string' }
            },
            required: ['relPath', 'content']
          },
          description: 'Optional bundled script files inside scripts/ to analyze together for cross-file taint flows.'
        }
      },
      required: ['content']
    }
  },
  {
    name: 'skill_xray_lock',
    description:
      'Generate or update an Ed25519 cryptographically signed skills.lock.json recording SHA-256 Merkle roots for all approved skills.',
    inputSchema: {
      type: 'object',
      properties: {
        paths: { type: 'array', items: { type: 'string' }, description: 'Paths to scan and lock.' },
        lock_path: { type: 'string', description: 'Output lockfile path (default: "skills.lock.json").' },
        key_dir: { type: 'string', description: 'Directory for Ed25519 keypair (default: ".skill-xray").' }
      }
    }
  },
  {
    name: 'skill_xray_verify',
    description:
      'Verify currently installed skills against an Ed25519 signed skills.lock.json to detect silent rug-pull tampering or drift.',
    inputSchema: {
      type: 'object',
      properties: {
        paths: { type: 'array', items: { type: 'string' }, description: 'Paths to scan for verification.' },
        lock_path: { type: 'string', description: 'Path to skills.lock.json (default: "skills.lock.json").' }
      }
    }
  }
];

export function handleMcpRequest(msg) {
  const { id, method, params = {} } = msg;

  if (method === 'notifications/initialized' || method === 'notifications/cancelled') {
    return null;
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO
      }
    };
  }

  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } };
  }

  if (method === 'tools/call') {
    const name = params.name;
    const args = params.arguments || {};

    try {
      let data;
      if (name === 'skill_xray_scan_path') {
        data = scanPaths(Array.isArray(args.paths) ? args.paths : []);
      } else if (name === 'skill_xray_scan_text') {
        data = scanSkillContent(args.content || '', {
          name: args.name || 'candidate-skill',
          scripts: Array.isArray(args.scripts) ? args.scripts : []
        });
      } else if (name === 'skill_xray_lock') {
        const report = scanPaths(Array.isArray(args.paths) ? args.paths : []);
        const res = createLockfile(report, {
          lockPath: args.lock_path || 'skills.lock.json',
          keyDir: args.key_dir || '.skill-xray'
        });
        data = {
          locked: true,
          lockPath: res.lockPath,
          publicKeyFingerprint: res.publicKeyFingerprint,
          skillCount: res.skillCount
        };
      } else if (name === 'skill_xray_verify') {
        const report = scanPaths(Array.isArray(args.paths) ? args.paths : []);
        data = verifyLockfile(args.lock_path || 'skills.lock.json', report);
      } else {
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }]
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [{ type: 'text', text: `skill-xray error: ${err.message}` }]
        }
      };
    }
  }

  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

export function startStdioMcpServer() {
  let buffer = Buffer.alloc(0);
  let useContentLength = false;

  const send = (payload) => {
    const json = JSON.stringify(payload);
    if (useContentLength) {
      process.stdout.write(`Content-Length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}`);
    } else {
      process.stdout.write(json + '\n');
    }
  };

  const dispatch = (raw) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    const resp = handleMcpRequest(msg);
    if (resp) send(resp);
  };

  process.stdin.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length > 0) {
      const str = buffer.toString('utf8');
      if (str.startsWith('Content-Length:')) {
        useContentLength = true;
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) break;
        const header = buffer.slice(0, headerEnd).toString('utf8');
        const m = header.match(/Content-Length:\s*(\d+)/i);
        if (!m) {
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
        const len = parseInt(m[1], 10);
        const total = headerEnd + 4 + len;
        if (buffer.length < total) break;
        const body = buffer.slice(headerEnd + 4, total).toString('utf8');
        buffer = buffer.slice(total);
        dispatch(body);
      } else {
        const nl = buffer.indexOf('\n');
        if (nl === -1) break;
        const line = buffer.slice(0, nl).toString('utf8');
        buffer = buffer.slice(nl + 1);
        dispatch(line);
      }
    }
  });
}
