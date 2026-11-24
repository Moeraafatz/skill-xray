import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Zero-Dependency Ed25519 Cryptographic Skill Lockfile (`skills.lock.json`).
 *
 * Prevents silent supply-chain rug pulls by hashing every file in every installed
 * skill bundle into a deterministic Merkle root and signing the manifest with Ed25519.
 */

export const LOCKFILE_VERSION = 1;

export function generateSigningKeyPair(keyDir = '.skill-xray') {
  fs.mkdirSync(keyDir, { recursive: true });
  const privPath = path.join(keyDir, 'ed25519.private.pem');
  const pubPath = path.join(keyDir, 'ed25519.public.pem');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      created: false,
      privateKeyPath: privPath,
      publicKeyPath: pubPath,
      privateKeyPem: fs.readFileSync(privPath, 'utf8'),
      publicKeyPem: fs.readFileSync(pubPath, 'utf8')
    };
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  fs.writeFileSync(privPath, privateKey, { encoding: 'utf8', mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { encoding: 'utf8', mode: 0o644 });

  return {
    created: true,
    privateKeyPath: privPath,
    publicKeyPath: pubPath,
    privateKeyPem: privateKey,
    publicKeyPem: publicKey
  };
}

function canonicalPayload(lockData) {
  const { signature, ...unsigned } = lockData;
  return JSON.stringify(unsigned);
}

export function createLockfile(scanReport, { lockPath = 'skills.lock.json', keyDir = '.skill-xray', baseDir = process.cwd() } = {}) {
  const keys = generateSigningKeyPair(keyDir);

  const entries = scanReport.skills
    .map((s) => ({
      name: s.name,
      kind: s.kind,
      rel_path: path.relative(baseDir, s.path).replace(/\\/g, '/') || path.basename(s.path),
      merkle_root: s.merkle_root,
      file_count: s.file_count,
      files: s.files.map((f) => ({ relPath: f.relPath, sha256: f.sha256 })),
      capabilities: s.capabilities,
      risk_score: s.risk_score,
      verdict: s.verdict
    }))
    .sort((a, b) => a.rel_path.localeCompare(b.rel_path) || a.name.localeCompare(b.name));

  const pubKeyFingerprint = crypto
    .createHash('sha256')
    .update(keys.publicKeyPem)
    .digest('hex')
    .slice(0, 16);

  const unsigned = {
    lockfile_version: LOCKFILE_VERSION,
    algorithm: 'Ed25519',
    public_key_fingerprint: pubKeyFingerprint,
    public_key_pem: keys.publicKeyPem,
    generated_at: new Date().toISOString(),
    skill_count: entries.length,
    skills: entries
  };

  const payload = Buffer.from(canonicalPayload(unsigned), 'utf8');
  const sig = crypto.sign(null, payload, keys.privateKeyPem).toString('base64');

  const signedLock = { ...unsigned, signature: sig };
  fs.mkdirSync(path.dirname(path.resolve(lockPath)), { recursive: true });
  fs.writeFileSync(lockPath, JSON.stringify(signedLock, null, 2) + '\n', 'utf8');

  return {
    lockPath: path.resolve(lockPath),
    publicKeyFingerprint: pubKeyFingerprint,
    keyCreated: keys.created,
    skillCount: entries.length,
    lockfile: signedLock
  };
}

export function verifyLockfile(lockPath, scanReport, { publicKeyPem = null, baseDir = process.cwd() } = {}) {
  if (!fs.existsSync(lockPath)) {
    return {
      ok: false,
      color: 'red',
      error: `Lockfile not found: ${lockPath}`,
      signature_valid: false,
      unchanged: [],
      tampered: [],
      added: [],
      removed: []
    };
  }

  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch (err) {
    return {
      ok: false,
      color: 'red',
      error: `Invalid JSON lockfile: ${err.message}`,
      signature_valid: false,
      unchanged: [],
      tampered: [],
      added: [],
      removed: []
    };
  }

  const pubPem = publicKeyPem || lock.public_key_pem;
  let signatureValid = false;
  try {
    const payload = Buffer.from(canonicalPayload(lock), 'utf8');
    const sigBuf = Buffer.from(lock.signature || '', 'base64');
    signatureValid = crypto.verify(null, payload, pubPem, sigBuf);
  } catch {
    signatureValid = false;
  }

  const lockedByPath = new Map((lock.skills || []).map((s) => [s.rel_path, s]));
  const liveByPath = new Map();
  for (const s of scanReport.skills || []) {
    const rel = path.relative(baseDir, s.path).replace(/\\/g, '/') || path.basename(s.path);
    liveByPath.set(rel, s);
  }

  const unchanged = [];
  const tampered = [];
  const added = [];
  const removed = [];

  for (const [rel, locked] of lockedByPath.entries()) {
    const live = liveByPath.get(rel);
    if (!live) {
      removed.push({ name: locked.name, rel_path: rel });
      continue;
    }
    if (live.merkle_root === locked.merkle_root) {
      unchanged.push({ name: locked.name, rel_path: rel, merkle_root: locked.merkle_root });
    } else {
      // Pinpoint exact modified/added/deleted files inside the tampered bundle!
      const lockedFiles = new Map((locked.files || []).map((f) => [f.relPath, f.sha256]));
      const liveFiles = new Map((live.files || []).map((f) => [f.relPath, f.sha256]));
      const changedFiles = [];
      for (const [fPath, hash] of liveFiles.entries()) {
        if (!lockedFiles.has(fPath)) changedFiles.push(`+${fPath}`);
        else if (lockedFiles.get(fPath) !== hash) changedFiles.push(`~${fPath}`);
      }
      for (const fPath of lockedFiles.keys()) {
        if (!liveFiles.has(fPath)) changedFiles.push(`-${fPath}`);
      }
      tampered.push({
        name: locked.name,
        rel_path: rel,
        expected_root: locked.merkle_root,
        actual_root: live.merkle_root,
        changed_files: changedFiles,
        live_verdict: live.verdict,
        live_score: live.risk_score
      });
    }
  }

  for (const [rel, live] of liveByPath.entries()) {
    if (!lockedByPath.has(rel)) {
      added.push({ name: live.name, rel_path: rel, verdict: live.verdict, risk_score: live.risk_score });
    }
  }

  const ok = signatureValid && tampered.length === 0 && added.length === 0 && removed.length === 0;
  const color = !signatureValid || tampered.length > 0 ? 'red' : added.length > 0 || removed.length > 0 ? 'yellow' : 'green';

  return {
    ok,
    color,
    verdict: color === 'red' ? 'TAMPERED' : color === 'yellow' ? 'DRIFT' : 'VERIFIED',
    signature_valid: signatureValid,
    public_key_fingerprint: lock.public_key_fingerprint || 'unknown',
    unchanged,
    tampered,
    added,
    removed
  };
}
