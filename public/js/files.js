// Client-side file checks (before encryption, since the server never sees plaintext)
// and watermark application / extraction.
import * as WM from '/shared/watermark-codec.js';
import { describeContent } from '/shared/content-sniff.js';

let PDFLib = null;
async function pdfLib() {
  if (!PDFLib) PDFLib = await import('/vendor/pdf-lib.esm.min.js');
  return PDFLib;
}

export const TYPES = {
  txt: { mime: 'text/plain', kind: 'text' },
  md: { mime: 'text/markdown', kind: 'text' },
  csv: { mime: 'text/csv', kind: 'text' },
  pdf: { mime: 'application/pdf', kind: 'pdf' },
  png: { mime: 'image/png', kind: 'image' },
  jpg: { mime: 'image/jpeg', kind: 'image' },
  jpeg: { mime: 'image/jpeg', kind: 'image' },
};

export const extOf = (name) => (/\.([A-Za-z0-9]{1,8})$/.exec(name)?.[1] || '').toLowerCase();

/** Facts the server needs to decide the upload (type, size, first bytes). The server makes the decision. */
export function uploadRequest(name, bytes) {
  const ext = extOf(name);
  return { filename: name, mimeType: TYPES[ext]?.mime || 'application/octet-stream', sizeBytes: bytes.length, content: describeContent(bytes) };
}

async function stampImage(bytes, mime, label) {
  const blob = new Blob([bytes], { type: mime });
  const bmp = await createImageBitmap(blob);
  const canvas = document.createElement('canvas');
  canvas.width = bmp.width;
  canvas.height = bmp.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bmp, 0, 0);
  const size = Math.max(12, Math.round(Math.min(bmp.width, bmp.height) / 22));
  ctx.font = `700 ${size}px sans-serif`;
  ctx.fillStyle = 'rgba(122, 31, 61, 0.22)';
  ctx.save();
  ctx.translate(bmp.width / 2, bmp.height / 2);
  ctx.rotate(-Math.PI / 7);
  const step = size * 4;
  for (let y = -bmp.height; y < bmp.height; y += step) {
    for (let x = -bmp.width; x < bmp.width; x += ctx.measureText(label).width + size * 2) ctx.fillText(label, x, y);
  }
  ctx.restore();
  ctx.fillStyle = 'rgba(255,255,255,0.85)';
  ctx.fillRect(0, bmp.height - size * 1.6, bmp.width, size * 1.6);
  ctx.fillStyle = '#7a1f3d';
  ctx.font = `${Math.round(size * 0.7)}px sans-serif`;
  ctx.fillText(WM.bannerText(label), size * 0.5, bmp.height - size * 0.5);
  const out = await new Promise((r) => canvas.toBlob(r, 'image/png'));
  return new Uint8Array(await out.arrayBuffer());
}

/**
 * Apply the server-issued watermark to a decrypted copy.
 * Returns { bytes, mime, filename, method }.
 */
export async function applyWatermark({ bytes, ext, filename, watermark }) {
  const kind = TYPES[ext]?.kind;
  const { payload, label } = watermark;
  if (kind === 'text') {
    const text = new TextDecoder().decode(bytes);
    const out = WM.embedText(text, payload, label, { format: ext });
    return { bytes: new TextEncoder().encode(out), mime: TYPES[ext].mime, filename, method: 'Visible banner and invisible zero-width signature' };
  }
  if (kind === 'pdf') {
    const out = await WM.embedPdf(await pdfLib(), bytes, payload, label);
    return { bytes: new Uint8Array(out), mime: 'application/pdf', filename, method: 'Footer and diagonal stamp on every page; signature in PDF metadata' };
  }
  if (kind === 'image') {
    const png = await stampImage(bytes, TYPES[ext].mime, label);
    const out = WM.insertPngText(png, WM.WM_KEYWORD, payload);
    return { bytes: out, mime: 'image/png', filename: filename.replace(/\.(jpe?g|png)$/i, '') + '.png', method: 'Tiled visible stamp; signature in PNG text chunk' };
  }
  throw new Error('Unsupported type for watermarking');
}

/** Find watermark payloads in a (possibly leaked) file. Runs entirely in the browser. */
export async function extractWatermarks(name, bytes) {
  const found = new Set();
  if (WM.isPng(bytes)) WM.extractFromPng(bytes).forEach((p) => found.add(p));
  if (bytes[0] === 0x25 && bytes[1] === 0x50) (await WM.extractFromPdf(await pdfLib(), bytes)).forEach((p) => found.add(p));
  try {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    WM.extractFromText(text).forEach((p) => found.add(p));
  } catch {
    /* binary */
  }
  return [...found];
}
