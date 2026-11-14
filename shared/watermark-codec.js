// VaultShare watermark codec (isomorphic ES module).
// The server issues a signed watermark payload per download ("VS1.<downloadId>.<tag>").
// The client embeds it into the decrypted copy before handing it to the user:
//   - text formats (.txt .md .csv): visible banner + invisible zero-width encoding (repeated)
//   - PNG / JPEG: visible tiled stamp (canvas, browser only) + PNG tEXt chunk
//   - PDF: visible stamp on every page + document Keywords/Subject (via pdf-lib)
// Extraction functions let an administrator trace a leaked copy back to a download.

export const WM_KEYWORD = 'VaultShare-Watermark';
export const PAYLOAD_RE = /VS1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{22}/g;

const ZW0 = '​'; // zero width space      -> bit 0
const ZW1 = '‌'; // zero width non-joiner  -> bit 1
const ZWS = '⁢'; // invisible times        -> start marker
const ZWE = '⁣'; // invisible separator    -> end marker
const enc = new TextEncoder();
const dec = new TextDecoder();

export function encodeZeroWidth(payload) {
  let bits = '';
  for (const byte of enc.encode(payload)) bits += byte.toString(2).padStart(8, '0');
  return ZWS + bits.replace(/0/g, ZW0).replace(/1/g, ZW1) + ZWE;
}

export function decodeZeroWidth(text) {
  const found = new Set();
  const re = new RegExp(`${ZWS}([${ZW0}${ZW1}]+)${ZWE}`, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    const bits = m[1].replace(new RegExp(ZW0, 'g'), '0').replace(new RegExp(ZW1, 'g'), '1');
    if (bits.length % 8 !== 0) continue;
    const bytes = new Uint8Array(bits.length / 8);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    found.add(dec.decode(bytes));
  }
  return [...found];
}

export function bannerText(label) {
  return `VaultShare confidential copy. ${label}`;
}

/**
 * Embed into a text document. A visible banner line is prepended (as a comment line
 * for CSV) and the invisible payload is repeated every `every` lines so that a
 * partial copy-paste usually still carries it.
 */
export function embedText(text, payload, label, { format = 'txt', every = 25 } = {}) {
  const zw = encodeZeroWidth(payload);
  const prefix = format === 'csv' ? '# ' : format === 'md' ? '> ' : '';
  const banner = `${prefix}${bannerText(label)}${zw}`;
  const lines = text.split('\n');
  const out = [];
  lines.forEach((line, i) => {
    out.push(i > 0 && i % every === 0 && line.length > 0 ? line + zw : line);
  });
  return `${banner}\n${out.join('\n')}`;
}

export function extractFromText(text) {
  const zw = decodeZeroWidth(text);
  const visible = text.match(PAYLOAD_RE) || [];
  return [...new Set([...zw, ...visible])].filter((p) => new RegExp(`^${PAYLOAD_RE.source}$`).test(p));
}

// ---------- PNG tEXt chunk ----------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export function isPng(bytes) {
  return PNG_SIG.every((b, i) => bytes[i] === b);
}

export function insertPngText(bytes, keyword, text) {
  if (!isPng(bytes)) throw new Error('NOT_A_PNG');
  const data = enc.encode(`${keyword}\0${text}`);
  const typeAndData = new Uint8Array(4 + data.length);
  typeAndData.set(enc.encode('tEXt'), 0);
  typeAndData.set(data, 4);
  const chunk = new Uint8Array(12 + data.length);
  const dv = new DataView(chunk.buffer);
  dv.setUint32(0, data.length);
  chunk.set(typeAndData, 4);
  dv.setUint32(8 + data.length, crc32(typeAndData));
  // insert right after IHDR (8 sig + 25 IHDR chunk)
  const ihdrLen = new DataView(bytes.buffer, bytes.byteOffset).getUint32(8);
  const at = 8 + 12 + ihdrLen;
  const out = new Uint8Array(bytes.length + chunk.length);
  out.set(bytes.subarray(0, at), 0);
  out.set(chunk, at);
  out.set(bytes.subarray(at), at + chunk.length);
  return out;
}

export function readPngText(bytes) {
  if (!isPng(bytes)) return [];
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = [];
  let off = 8;
  while (off + 12 <= bytes.length) {
    const len = dv.getUint32(off);
    const type = dec.decode(bytes.subarray(off + 4, off + 8));
    if (type === 'tEXt') {
      const body = dec.decode(bytes.subarray(off + 8, off + 8 + len));
      const nul = body.indexOf('\0');
      if (nul > 0) out.push({ keyword: body.slice(0, nul), text: body.slice(nul + 1) });
    }
    if (type === 'IEND') break;
    off += 12 + len;
  }
  return out;
}

export function extractFromPng(bytes) {
  return readPngText(bytes)
    .filter((c) => c.keyword === WM_KEYWORD)
    .map((c) => c.text);
}

// ---------- PDF (pdf-lib passed in so this module stays dependency-free) ----------
export async function embedPdf(PDFLib, bytes, payload, label) {
  const { PDFDocument, StandardFonts, rgb, degrees } = PDFLib;
  const doc = await PDFDocument.load(bytes, { updateMetadata: false });
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const stamp = bannerText(label);
  for (const page of doc.getPages()) {
    const { width, height } = page.getSize();
    page.drawText(stamp, { x: 24, y: 14, size: 7, font, color: rgb(0.45, 0.1, 0.18), opacity: 0.85 });
    page.drawText('CONFIDENTIAL', {
      x: width * 0.18,
      y: height * 0.35,
      size: Math.min(width, height) / 9,
      font,
      color: rgb(0.55, 0.11, 0.2),
      opacity: 0.08,
      rotate: degrees(35),
    });
  }
  doc.setKeywords([WM_KEYWORD, payload]);
  doc.setSubject(`${WM_KEYWORD} ${payload}`);
  return doc.save();
}

export async function extractFromPdf(PDFLib, bytes) {
  try {
    const doc = await PDFLib.PDFDocument.load(bytes, { updateMetadata: false });
    const text = `${doc.getKeywords() || ''} ${doc.getSubject() || ''}`;
    return [...new Set(text.match(PAYLOAD_RE) || [])];
  } catch {
    return [];
  }
}
