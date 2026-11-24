/**
 * Unicode Steganography & Trojan Source Analyzer.
 *
 * Grounded in:
 * - Boucher & Anderson (2021), "Trojan Source: Invisible Vulnerabilities" (arXiv:2111.00169)
 * - Unicode Tag Block Steganography (U+E0000..U+E007F) used in hidden prompt injections
 * - Invisible HTML/Markdown comment directive smuggling
 */

const BIDI_CONTROLS = new Set([
  0x202a, // LRE
  0x202b, // RLE
  0x202c, // PDF
  0x202d, // LRO
  0x202e, // RLO (classic Trojan Source attack)
  0x2066, // LRI
  0x2067, // RLI
  0x2068, // FSI
  0x2069  // PDI
]);

const ZERO_WIDTH_CHARS = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0x2060, // WORD JOINER
  0xfeff  // BOM / ZERO WIDTH NO-BREAK SPACE
]);

// High-risk Cyrillic/Greek confusable lookalikes inside Latin identifiers/commands
const CONFUSABLES = new Map([
  ['\u0430', 'a'], ['\u0435', 'e'], ['\u043e', 'o'], ['\u0440', 'p'],
  ['\u0441', 'c'], ['\u0443', 'y'], ['\u0445', 'x'], ['\u0456', 'i'],
  ['\u0410', 'A'], ['\u0415', 'E'], ['\u041e', 'O'], ['\u0420', 'P'],
  ['\u0421', 'C'], ['\u0425', 'X'], ['\u03bf', 'o'], ['\u03b1', 'a'],
  ['\u03b5', 'e'], ['\u03c1', 'p']
]);

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

export function analyzeUnicodeAndStego(text, relPath) {
  const findings = [];
  if (!text) return findings;

  // 1. Unicode Tag Characters (U+E0000..U+E007F) — decode hidden ASCII message!
  let tagDecoded = '';
  let tagCount = 0;
  let firstTagOffset = -1;
  let offset = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      if (firstTagOffset === -1) firstTagOffset = offset;
      tagCount++;
      if (cp >= 0xe0020 && cp <= 0xe007e) {
        tagDecoded += String.fromCharCode(cp - 0xe0000);
      }
    }
    offset += ch.length;
  }

  if (tagCount >= 3) {
    findings.push({
      id: 'UNICODE_TAG_STEGO',
      category: 'steganography',
      severity: 'critical',
      score: 70,
      file: relPath,
      line: lineAt(text, firstTagOffset),
      title: `Invisible Unicode Tag payload detected (${tagCount} hidden codepoints)`,
      evidence: tagDecoded
        ? `Decoded hidden ASCII: "${tagDecoded.slice(0, 140)}"`
        : `${tagCount} invisible U+E0000..U+E007F tag characters`,
      remediation: 'Remove all U+E0000..U+E007F invisible tag characters; reject this skill immediately.'
    });
  }

  // 2. Trojan Source BiDi Control Characters
  const bidiHits = [];
  offset = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (BIDI_CONTROLS.has(cp)) {
      bidiHits.push({ cp, offset });
    }
    offset += ch.length;
  }
  if (bidiHits.length > 0) {
    const codes = [...new Set(bidiHits.map((b) => 'U+' + b.cp.toString(16).toUpperCase().padStart(4, '0')))];
    findings.push({
      id: 'TROJAN_SOURCE_BIDI',
      category: 'steganography',
      severity: 'critical',
      score: 60,
      file: relPath,
      line: lineAt(text, bidiHits[0].offset),
      title: `Trojan Source BiDi override characters detected (${bidiHits.length} occurrences)`,
      evidence: `BiDi controls: ${codes.join(', ')}`,
      remediation: 'Strip bidirectional override characters (arXiv:2111.00169) before trusting commands or prose.'
    });
  }

  // 3. Zero-Width Steganography Clusters (ignoring BOM at index 0 and legitimate emoji ZWJ joins)
  let zwCount = 0;
  let firstZwOffset = -1;
  offset = 0;
  const chars = [...text];
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i].codePointAt(0);
    if (ZERO_WIDTH_CHARS.has(cp)) {
      const isBom = cp === 0xfeff && i === 0;
      const prevCp = i > 0 ? chars[i - 1].codePointAt(0) : 0;
      const nextCp = i + 1 < chars.length ? chars[i + 1].codePointAt(0) : 0;
      const isEmojiZwj = cp === 0x200d && (prevCp >= 0x1f000 || nextCp >= 0x1f000 || prevCp === 0xfe0f);
      if (!isBom && !isEmojiZwj) {
        if (firstZwOffset === -1) firstZwOffset = offset;
        zwCount++;
      }
    }
    offset += chars[i].length;
  }

  if (zwCount >= 4) {
    findings.push({
      id: 'ZERO_WIDTH_STEGO',
      category: 'steganography',
      severity: 'high',
      score: 38,
      file: relPath,
      line: lineAt(text, firstZwOffset),
      title: `Suspicious zero-width character cluster (${zwCount} invisible chars)`,
      evidence: `Found ${zwCount} non-emoji zero-width characters (U+200B/200C/200D/2060/FEFF)`,
      remediation: 'Inspect and normalize invisible whitespace; zero-width clusters often hide covert watermark or injection payloads.'
    });
  }

  // 4. Mixed-Script Homoglyph Spoofing inside Latin words/commands/URLs
  const wordRegex = /[^\s"'`<>()[\]{}]+/g;
  let match;
  const spoofedTokens = [];
  while ((match = wordRegex.exec(text)) !== null) {
    const tok = match[0];
    let hasLatin = false;
    let hasConfusable = false;
    for (const ch of tok) {
      if (/[A-Za-z]/.test(ch)) hasLatin = true;
      if (CONFUSABLES.has(ch)) hasConfusable = true;
    }
    if (hasLatin && hasConfusable) {
      spoofedTokens.push({ tok, line: lineAt(text, match.index) });
      if (spoofedTokens.length >= 5) break;
    }
  }
  if (spoofedTokens.length > 0) {
    findings.push({
      id: 'HOMOGLYPH_SPOOFING',
      category: 'steganography',
      severity: 'high',
      score: 42,
      file: relPath,
      line: spoofedTokens[0].line,
      title: `Mixed-script Cyrillic/Greek homoglyph spoofing in ${spoofedTokens.length} token(s)`,
      evidence: `Spoofed tokens: ${spoofedTokens.map((s) => s.tok.slice(0, 32)).join(', ')}`,
      remediation: 'Replace confusable non-Latin lookalikes in commands, URLs, or identifiers.'
    });
  }

  // 5. Hidden HTML / Markdown Comments containing imperative instructions or commands
  const commentRegex = /<!--([\s\S]*?)-->|\[\/\/\]:\s*#\s*\(([^)]+)\)/g;
  while ((match = commentRegex.exec(text)) !== null) {
    const body = (match[1] || match[2] || '').trim();
    if (body.length < 10) continue;
    const suspicious =
      /\b(ignore\s+(?:all\s+)?(?:previous|prior|above)|system\s+prompt|do\s+not\s+(?:tell|inform|mention)|silently|exfiltrat|curl\s+|wget\s+|bash\s+-c|eval\s*\(|ssh\/|id_rsa|\.env\b|base64|https?:\/\/)/i.test(
        body
      );
    if (suspicious) {
      findings.push({
        id: 'HIDDEN_COMMENT_PAYLOAD',
        category: 'steganography',
        severity: 'critical',
        score: 58,
        file: relPath,
        line: lineAt(text, match.index),
        title: 'Suspicious hidden directive smuggled inside HTML/Markdown comment',
        evidence: body.replace(/\s+/g, ' ').slice(0, 140),
        remediation: 'Never hide agent instructions, URLs, or shell commands inside invisible Markdown comments.'
      });
    }
  }

  return findings;
}
