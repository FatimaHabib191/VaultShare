// File-content inspection shared by the browser and the server.
// The browser runs `describeContent` on the plaintext before encryption and sends
// the small, non-sensitive summary (first 8 bytes, UTF-8 validity, NUL presence)
// with the upload request. The server then makes the decision itself with
// `checkContent`, so the rule, evidence and audit record live on the server even
// though the server never sees the file contents.

export const KIND_BY_EXT = { txt: 'text', md: 'text', csv: 'text', pdf: 'pdf', png: 'png', jpg: 'jpeg', jpeg: 'jpeg' };

const SIGNATURES = [
  ['pdf', [0x25, 0x50, 0x44, 0x46, 0x2d]], // %PDF-
  ['png', [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  ['jpeg', [0xff, 0xd8, 0xff]],
  ['exe', [0x4d, 0x5a]], // MZ: Windows executable
  ['elf', [0x7f, 0x45, 0x4c, 0x46]],
  ['zip', [0x50, 0x4b, 0x03, 0x04]],
];

const LABEL = { pdf: 'a PDF', png: 'a PNG image', jpeg: 'a JPEG image', exe: 'a Windows executable', elf: 'a Linux executable', zip: 'a ZIP archive', text: 'plain text', binary: 'unrecognised binary data' };

/** Runs in the browser on the plaintext. Returns only non-sensitive facts. */
export function describeContent(bytes) {
  const head = Array.from(bytes.subarray(0, 8), (b) => b.toString(16).padStart(2, '0')).join('');
  let utf8 = true;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    utf8 = false;
  }
  return { headHex: head, utf8, hasNul: bytes.includes(0) };
}

export function detectKind({ headHex, utf8, hasNul }) {
  const head = (headHex.match(/../g) || []).map((h) => parseInt(h, 16));
  for (const [kind, sig] of SIGNATURES) if (sig.every((b, i) => head[i] === b)) return kind;
  return utf8 && !hasNul ? 'text' : 'binary';
}

/** Server-side rule. Returns null when the content matches the extension. */
export function checkContent(extension, summary) {
  const expected = KIND_BY_EXT[extension];
  const detected = detectKind(summary);
  if (!expected) return { ok: false, expected: null, detected, message: `Files ending in .${extension} are not supported.` };
  if (expected === detected) return { ok: true, expected, detected };
  return {
    ok: false,
    expected,
    detected,
    message: `The file is named .${extension} but its contents are ${LABEL[detected] || detected}, not ${LABEL[expected]}.`,
  };
}
