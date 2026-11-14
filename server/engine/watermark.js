// Server half of FR-5. The server cannot see plaintext, so it issues a signed,
// per-download watermark payload; the client embeds it in the decrypted copy.
// A leaked copy can be traced: the payload's HMAC proves it was issued by this
// server and identifies the exact download (user, grant, document, time).
import { createHmac, timingSafeEqual } from 'node:crypto';

export const WATERMARK_VERSION = 'VS1';
const PAYLOAD_RE = /^VS1\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{22})$/;

function tagFor(key, { downloadId, grantId, userId, documentId }) {
  return createHmac('sha256', key)
    .update(`${WATERMARK_VERSION}|${downloadId}|${grantId}|${userId}|${documentId}`)
    .digest()
    .subarray(0, 16)
    .toString('base64url');
}

export function issuePayload(key, fields) {
  return `${WATERMARK_VERSION}.${fields.downloadId}.${tagFor(key, fields)}`;
}

export function parsePayload(payload) {
  const m = typeof payload === 'string' ? PAYLOAD_RE.exec(payload.trim()) : null;
  return m ? { downloadId: m[1], tag: m[2] } : null;
}

/** downloadRecord: row from downloads table (or null). */
export function verifyPayload(key, payload, downloadRecord) {
  const parsed = parsePayload(payload);
  if (!parsed) return { valid: false, rule: 'WATERMARK_MALFORMED', reason: 'The text is not a VaultShare watermark payload.' };
  if (!downloadRecord) return { valid: false, rule: 'WATERMARK_UNKNOWN', reason: 'No download with this reference exists.' };
  const expected = Buffer.from(
    tagFor(key, {
      downloadId: downloadRecord.id,
      grantId: downloadRecord.grant_id,
      userId: downloadRecord.user_id,
      documentId: downloadRecord.document_id,
    })
  );
  const got = Buffer.from(parsed.tag);
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    return { valid: false, rule: 'WATERMARK_FORGED', reason: 'The reference exists but the signature does not match; the payload was altered or forged.' };
  }
  return { valid: true, rule: 'WATERMARK_VERIFIED', reason: 'Signature valid; the copy traces to the download below.' };
}

export function label({ username, issuedAt, downloadId }) {
  return `Issued to ${username} on ${new Date(issuedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC, ref ${downloadId.slice(0, 8)}`;
}
