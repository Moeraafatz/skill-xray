import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPaths, scanSkillContent } from '../core/scanner.js';
import { createLockfile, verifyLockfile } from '../core/lockfile.js';
import { handleMcpRequest } from '../mcp/server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIR = path.resolve(__dirname, '../../web');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8'
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > 2 * 1024 * 1024) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(JSON.stringify(data));
}

export function createHttpServer({ initialTargets = [] } = {}) {
  const handler = async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
      });
      return res.end();
    }

    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    try {
      if (pathname === '/api/health' && req.method === 'GET') {
        return sendJson(res, 200, { status: 'ok', engine: 'skill-xray', version: '1.0.0' });
      }

      if (pathname === '/mcp' && req.method === 'POST') {
        const body = await readBody(req);
        const reply = handleMcpRequest(body);
        if (!reply) {
          res.writeHead(202);
          return res.end();
        }
        return sendJson(res, 200, reply);
      }

      if (pathname === '/api/scan-paths' && req.method === 'POST') {
        const body = await readBody(req);
        const targets = Array.isArray(body.paths) && body.paths.length > 0 ? body.paths : initialTargets;
        return sendJson(res, 200, scanPaths(targets));
      }

      if (pathname === '/api/scan-text' && req.method === 'POST') {
        const body = await readBody(req);
        const result = scanSkillContent(body.content || '', {
          name: body.name || 'pasted-skill',
          filename: body.filename || 'SKILL.md',
          scripts: Array.isArray(body.scripts) ? body.scripts : []
        });
        return sendJson(res, 200, result);
      }

      if (pathname === '/api/lock' && req.method === 'POST') {
        const body = await readBody(req);
        const report = scanPaths(Array.isArray(body.paths) ? body.paths : initialTargets);
        const result = createLockfile(report, { lockPath: body.lock_path || 'skills.lock.json' });
        return sendJson(res, 200, {
          locked: true,
          lockPath: result.lockPath,
          publicKeyFingerprint: result.publicKeyFingerprint,
          skillCount: result.skillCount
        });
      }

      if (pathname === '/api/verify' && req.method === 'POST') {
        const body = await readBody(req);
        const report = scanPaths(Array.isArray(body.paths) ? body.paths : initialTargets);
        const result = verifyLockfile(body.lock_path || 'skills.lock.json', report);
        return sendJson(res, 200, result);
      }

      const safePath = pathname === '/' ? '/index.html' : pathname;
      const fullPath = path.resolve(WEB_DIR, '.' + safePath);
      if (fullPath.startsWith(WEB_DIR) && fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        const ext = path.extname(fullPath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        fs.createReadStream(fullPath).pipe(res);
        return;
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      sendJson(res, 400, { error: err.message });
    }
  };

  const server = http.createServer(handler);
  return { server, handler };
}
